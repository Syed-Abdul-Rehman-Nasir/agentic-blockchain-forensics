"""ArtifactAnalysisAgent — forensic collection / parsing agent.

Committee note: this agent owns disk mounting and artifact extraction
(pytsk3, registry, EVTX/EVT, browser, prefetch). It does NOT run ML scoring;
that is ThreatInterpretationAgent's job. Agents run sequentially, never in
parallel, to avoid SQLite lock conflicts on a single-investigator machine.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Set

from ai_service.agents.base_agent import BaseAgent
from ai_service.db.database import (
    create_case,
    get_connection,
    mark_stage_complete,
)
from ai_service.parsers.browser_parser import parse_chrome_history
from ai_service.parsers.disk_mount import ingest_e01, mount_image
from ai_service.parsers.evtx_parser import parse_all_evtx
from ai_service.parsers.prefetch_parser import parse_prefetch
from ai_service.parsers.registry_parser import parse_all_registry
from ai_service.parsers.windows_extras_parser import (
    parse_lnk_files,
    parse_recycle_bin,
    parse_scheduled_tasks,
)

logger = logging.getLogger(__name__)

PARSE_STAGES = ("registry", "events", "browser", "prefetch")
WINDOWS_EXTRA_STAGES = ("scheduled_tasks", "recycle_bin", "lnk_files")


class ArtifactAnalysisAgent(BaseAgent):
    """Collection Agent: mount image and extract structured forensic artifacts."""

    def analyse(
        self,
        case_id: str,
        image_path: str,
        conn=None,
    ) -> Dict[str, Any]:
        owns = conn is None
        if owns:
            conn = get_connection()

        try:
            self.log_action(
                case_id,
                "artifact_analysis_started",
                f"image_path={image_path}",
                conn=conn,
            )

            self._ensure_case(case_id, image_path, conn)
            completed: Set[str] = set(self.get_completed_stages(case_id, conn=conn))

            hashes = {"acquisition_hash": None, "system_hash": None}
            file_count = 0

            # Stage 1: disk mount / dual hash / filesystem walk
            if "disk_mount" not in completed:
                result = ingest_e01(case_id, image_path, conn)
                file_count = int(result["file_count"])
                hashes = {
                    "acquisition_hash": result["acquisition_hash"],
                    "system_hash": result["system_hash"],
                }
                completed.add("disk_mount")
            else:
                file_count, hashes = self._load_mount_summary(case_id, conn)

            # Windows path — core parsers + extras
            self._run_windows_parsers(case_id, image_path, conn, completed)

            counts = self._count_artifacts(case_id, conn)
            total = sum(counts.values())
            self.log_action(
                case_id,
                "artifact_analysis_completed",
                f"Artifact analysis completed — {total} artifacts extracted",
                conn=conn,
            )

            return {
                "file_count": file_count,
                "registry_count": counts["registry"],
                "event_count": counts["events"],
                "browser_count": counts["browser"],
                "prefetch_count": counts["prefetch"],
                "hashes": hashes,
            }
        finally:
            if owns:
                conn.close()

    def _run_windows_parsers(
        self, case_id: str, image_path: str, conn, completed: Set[str]
    ) -> None:
        missing_core = [s for s in PARSE_STAGES if s not in completed]
        missing_extra = [s for s in WINDOWS_EXTRA_STAGES if s not in completed]
        if not missing_core and not missing_extra:
            return

        img_info, fs_info = mount_image(image_path)
        try:
            if "registry" in missing_core:
                parse_all_registry(fs_info, case_id, conn)
                completed.add("registry")
            if "events" in missing_core:
                parse_all_evtx(fs_info, case_id, conn)
                completed.add("events")
            if "browser" in missing_core:
                parse_chrome_history(fs_info, case_id, conn)
                completed.add("browser")
            if "prefetch" in missing_core:
                parse_prefetch(fs_info, case_id, conn)
                completed.add("prefetch")

            # Windows extras — non-fatal, each wrapped individually
            if "scheduled_tasks" in missing_extra:
                try:
                    parse_scheduled_tasks(fs_info, case_id, conn)
                    mark_stage_complete(case_id, "scheduled_tasks", conn=conn)
                    completed.add("scheduled_tasks")
                except Exception as exc:
                    logger.warning("Scheduled tasks parser failed: %s", exc)

            if "recycle_bin" in missing_extra:
                try:
                    parse_recycle_bin(fs_info, case_id, conn)
                    mark_stage_complete(case_id, "recycle_bin", conn=conn)
                    completed.add("recycle_bin")
                except Exception as exc:
                    logger.warning("Recycle Bin parser failed: %s", exc)

            if "lnk_files" in missing_extra:
                try:
                    parse_lnk_files(conn, case_id)
                    mark_stage_complete(case_id, "lnk_files", conn=conn)
                    completed.add("lnk_files")
                except Exception as exc:
                    logger.warning("LNK parser failed: %s", exc)
        finally:
            close = getattr(img_info, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    logger.debug(
                        "Error closing image handle for case %s: %s",
                        case_id,
                        exc,
                    )

    def _ensure_case(self, case_id: str, image_path: str, conn) -> None:
        row = conn.execute(
            "SELECT case_id FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if row is None:
            create_case(case_id, case_id, image_path, conn=conn)

    def _load_mount_summary(self, case_id: str, conn):
        case = conn.execute(
            """
            SELECT acquisition_hash, system_hash FROM cases WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()
        file_count = conn.execute(
            "SELECT COUNT(*) AS c FROM files WHERE case_id = ?",
            (case_id,),
        ).fetchone()["c"]
        hashes = {
            "acquisition_hash": case["acquisition_hash"] if case else None,
            "system_hash": case["system_hash"] if case else None,
        }
        return int(file_count), hashes

    def _count_artifacts(self, case_id: str, conn) -> Dict[str, int]:
        return {
            "registry": conn.execute(
                "SELECT COUNT(*) AS c FROM registry_entries WHERE case_id = ?",
                (case_id,),
            ).fetchone()["c"],
            "events": conn.execute(
                "SELECT COUNT(*) AS c FROM event_logs WHERE case_id = ?",
                (case_id,),
            ).fetchone()["c"],
            "browser": conn.execute(
                "SELECT COUNT(*) AS c FROM browser_history WHERE case_id = ?",
                (case_id,),
            ).fetchone()["c"],
            "prefetch": conn.execute(
                "SELECT COUNT(*) AS c FROM prefetch_entries WHERE case_id = ?",
                (case_id,),
            ).fetchone()["c"],
        }
