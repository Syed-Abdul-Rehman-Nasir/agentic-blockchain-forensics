"""SQLite persistence for cases, artifacts, and analysis stages.

WAL mode is mandatory on every connection to avoid 'database is locked'
errors when agents write sequentially on a single-investigator machine.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Project root: ai_service/db/database.py -> parents[2]
_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Configurable so tests can point at a temp DB without touching production data.
DB_PATH = os.environ.get(
    "FORENSIC_DB_PATH",
    str(_PROJECT_ROOT / "data" / "forensic.db"),
)


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode and Row factory."""
    path = db_path or DB_PATH
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    # WAL + foreign_keys must run immediately after connect (project rule).
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def initialise_db(db_path: Optional[str] = None) -> None:
    """Create all forensic tables if they do not already exist."""
    conn = get_connection(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                name TEXT,
                image_path TEXT,
                acquisition_hash TEXT,
                system_hash TEXT,
                created_at TEXT,
                status TEXT DEFAULT 'pending'
            );

            CREATE TABLE IF NOT EXISTS files (
                file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                path TEXT,
                size INTEGER,
                created TEXT,
                modified TEXT,
                accessed TEXT,
                extension TEXT,
                inode INTEGER
            );

            CREATE TABLE IF NOT EXISTS registry_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                hive TEXT,
                key_path TEXT,
                value_name TEXT,
                value_data TEXT,
                timestamp TEXT
            );

            CREATE TABLE IF NOT EXISTS event_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                event_id INTEGER,
                channel TEXT,
                timestamp TEXT,
                user_name TEXT,
                computer TEXT,
                description TEXT,
                raw_xml TEXT
            );

            CREATE TABLE IF NOT EXISTS browser_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                browser TEXT,
                url TEXT,
                title TEXT,
                visit_time TEXT,
                visit_count INTEGER
            );

            CREATE TABLE IF NOT EXISTS prefetch_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                executable TEXT,
                run_count INTEGER,
                last_run TEXT,
                volume_path TEXT
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                artifact_type TEXT,
                data_json TEXT,
                xgboost_score REAL,
                autoencoder_score REAL,
                flagged INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS analysis_stages (
                case_id TEXT,
                stage_name TEXT,
                completed_at TEXT,
                PRIMARY KEY (case_id, stage_name)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT,
                action TEXT,
                timestamp TEXT,
                details TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_prefetch_case_run
                ON prefetch_entries (case_id, last_run DESC);

            CREATE INDEX IF NOT EXISTS idx_events_case_ts
                ON event_logs (case_id, timestamp DESC);

            CREATE INDEX IF NOT EXISTS idx_events_case_id_ts
                ON event_logs (case_id, event_id, timestamp DESC);

            CREATE INDEX IF NOT EXISTS idx_registry_case_key
                ON registry_entries (case_id, key_path);

            CREATE INDEX IF NOT EXISTS idx_browser_case_time
                ON browser_history (case_id, visit_time DESC);

            CREATE INDEX IF NOT EXISTS idx_files_case_ext
                ON files (case_id, extension);

            CREATE INDEX IF NOT EXISTS idx_files_case_path
                ON files (case_id, path);

            CREATE INDEX IF NOT EXISTS idx_artifacts_case_flagged
                ON artifacts (case_id, flagged, xgboost_score DESC);
            """
        )
        conn.commit()
    finally:
        conn.close()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_case(
    case_id: str,
    name: str,
    image_path: str,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Insert a new case row with status 'pending'."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO cases (case_id, name, image_path, created_at, status)
            VALUES (?, ?, ?, ?, 'pending')
            """,
            (case_id, name, image_path, _utc_now()),
        )
        conn.commit()
    finally:
        if owns:
            conn.close()


def update_case_hashes(
    case_id: str,
    acquisition_hash: Optional[str],
    system_hash: Optional[str],
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Store both on-chain hashes: acquisition (ewfinfo/MD5) and system (SHA-256)."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        conn.execute(
            """
            UPDATE cases
            SET acquisition_hash = ?, system_hash = ?
            WHERE case_id = ?
            """,
            (acquisition_hash, system_hash, case_id),
        )
        conn.commit()
    finally:
        if owns:
            conn.close()


def update_case_status(
    case_id: str,
    status: str,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Update case lifecycle status (pending, mounting, analysing, complete, error)."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        conn.execute(
            "UPDATE cases SET status = ? WHERE case_id = ?",
            (status, case_id),
        )
        conn.commit()
    finally:
        if owns:
            conn.close()


def mark_stage_complete(
    case_id: str,
    stage_name: str,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Record that an analysis pipeline stage finished for this case."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO analysis_stages (case_id, stage_name, completed_at)
            VALUES (?, ?, ?)
            """,
            (case_id, stage_name, _utc_now()),
        )
        conn.commit()
    finally:
        if owns:
            conn.close()


def get_completed_stages(
    case_id: str,
    conn: Optional[sqlite3.Connection] = None,
) -> List[str]:
    """Return list of completed stage names for a case."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT stage_name FROM analysis_stages WHERE case_id = ? ORDER BY completed_at",
            (case_id,),
        ).fetchall()
        return [row["stage_name"] for row in rows]
    finally:
        if owns:
            conn.close()


def log_audit(
    case_id: str,
    action: str,
    details: str,
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Append an investigator/system action to the local audit_log table."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO audit_log (case_id, action, timestamp, details)
            VALUES (?, ?, ?, ?)
            """,
            (case_id, action, _utc_now(), details),
        )
        conn.commit()
    finally:
        if owns:
            conn.close()


def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[dict]:
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def get_case(
    case_id: str,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[dict]:
    """Return a single case row as a dict, or None."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        return _row_to_dict(row)
    finally:
        if owns:
            conn.close()


def list_cases(conn: Optional[sqlite3.Connection] = None) -> List[dict]:
    """Return all cases ordered by created_at descending."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM cases ORDER BY created_at DESC"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]  # type: ignore[misc]
    finally:
        if owns:
            conn.close()


def get_artifacts_for_case(
    case_id: str,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Return structured forensic artifacts for a case from all SQLite tables."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        def _count(table: str) -> int:
            return int(
                conn.execute(
                    f"SELECT COUNT(*) AS c FROM {table} WHERE case_id = ?",
                    (case_id,),
                ).fetchone()["c"]
            )

        def _fetch(sql: str) -> List[dict]:
            return [_row_to_dict(r) for r in conn.execute(sql, (case_id,)).fetchall()]  # type: ignore[misc]

        file_count = _count("files")
        registry_count = _count("registry_entries")
        event_count = _count("event_logs")
        browser_count = _count("browser_history")
        prefetch_count = _count("prefetch_entries")
        flagged_count = int(
            conn.execute(
                "SELECT COUNT(*) AS c FROM artifacts WHERE case_id = ? AND flagged = 1",
                (case_id,),
            ).fetchone()["c"]
        )

        return {
            # Flat counts (UI / report consumers)
            "file_count": file_count,
            "registry_count": registry_count,
            "event_count": event_count,
            "browser_count": browser_count,
            "prefetch_count": prefetch_count,
            "flagged_count": flagged_count,
            # Rows grouped by type (files omitted — metadata listing can be 10k+ rows)
            "registry": _fetch(
                "SELECT * FROM registry_entries WHERE case_id = ? ORDER BY id"
            ),
            "events": _fetch(
                "SELECT * FROM event_logs WHERE case_id = ? ORDER BY id"
            ),
            "browser": _fetch(
                "SELECT * FROM browser_history WHERE case_id = ? ORDER BY id"
            ),
            "prefetch": _fetch(
                "SELECT * FROM prefetch_entries WHERE case_id = ? ORDER BY id"
            ),
            "scored": _fetch(
                "SELECT * FROM artifacts WHERE case_id = ? ORDER BY id"
            ),
            # Nested counts kept for orchestrator / dashboard compatibility
            "counts": {
                "files": file_count,
                "registry": registry_count,
                "events": event_count,
                "browser": browser_count,
                "prefetch": prefetch_count,
                "scored": _count("artifacts"),
                "flagged": flagged_count,
            },
        }
    finally:
        if owns:
            conn.close()


def get_threats_for_case(
    case_id: str,
    conn: Optional[sqlite3.Connection] = None,
) -> List[dict]:
    """Return scored/flagged threat assessment rows from the artifacts table."""
    owns = conn is None
    if owns:
        conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT * FROM artifacts
            WHERE case_id = ?
            ORDER BY COALESCE(xgboost_score, 0) DESC, id
            """,
            (case_id,),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]  # type: ignore[misc]
    finally:
        if owns:
            conn.close()
