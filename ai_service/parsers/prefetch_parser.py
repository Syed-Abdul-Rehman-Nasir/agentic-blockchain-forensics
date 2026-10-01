"""Windows Prefetch (.pf) parser using libscca (pyscca).

Reveals program execution — high forensic value. NIST SCHARDT includes
CAIN.EXE, ETHEREAL.EXE, IEXPLORE.EXE and other tool prefetch files.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

from ai_service.db.database import mark_stage_complete
from ai_service.parsers.extract_utils import (
    extract_file,
    find_files,
    safe_unlink,
    temp_path_for,
)


def _dt_iso(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _parse_pf_file(temp_path: str, case_id: str, conn) -> bool:
    import pyscca

    pf = pyscca.file()
    pf.open(temp_path)
    try:
        executable = pf.get_executable_filename()
        run_count = pf.get_run_count()
        last_run = None
        try:
            last_run = _dt_iso(pf.get_last_run_time(0))
        except Exception:
            try:
                last_run = _dt_iso(pf.get_last_run_time())
            except Exception:
                last_run = None

        volume_path = None
        try:
            if pf.get_number_of_volumes() > 0:
                vol = pf.get_volume_information(0)
                volume_path = vol.get_device_path()
        except Exception:
            volume_path = None

        conn.execute(
            """
            INSERT INTO prefetch_entries
                (case_id, executable, run_count, last_run, volume_path)
            VALUES (?, ?, ?, ?, ?)
            """,
            (case_id, executable, run_count, last_run, volume_path),
        )
        return True
    finally:
        pf.close()


def parse_prefetch(fs_info, case_id: str, conn) -> Dict[str, int]:
    """Find .pf files, extract/parse each with pyscca, mark stage 'prefetch'."""
    paths = find_files(
        conn,
        case_id,
        ["%/Prefetch/%.pf", "%/prefetch/%.pf", "%.pf"],
    )
    # Keep only real prefetch files under a Prefetch directory when possible
    pf_paths = [
        p
        for p in paths
        if p.lower().endswith(".pf") and "prefetch" in p.lower()
    ]
    if not pf_paths:
        pf_paths = [p for p in paths if p.lower().endswith(".pf")]

    parsed = 0
    failed = 0
    for path in pf_paths:
        temp = temp_path_for("prefetch", ".pf")
        try:
            extract_file(fs_info, path, temp)
            if _parse_pf_file(temp, case_id, conn):
                parsed += 1
            else:
                failed += 1
        except Exception:
            failed += 1
        finally:
            safe_unlink(temp)

    conn.commit()
    mark_stage_complete(case_id, "prefetch", conn=conn)
    return {"parsed": parsed, "failed": failed, "found": len(pf_paths)}
