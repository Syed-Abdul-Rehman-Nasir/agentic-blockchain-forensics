"""Phase 2 parser tests against the NIST SCHARDT raw image.

Uses a temp DB seeded with file-index rows from data/forensic.db (TEST_NIST)
so parsers can locate artifacts without re-walking the whole filesystem.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import ai_service.db.database as database
from ai_service.db.database import get_connection, initialise_db
from ai_service.parsers.browser_parser import parse_chrome_history
from ai_service.parsers.disk_mount import mount_image
from ai_service.parsers.evtx_parser import parse_all_evtx
from ai_service.parsers.prefetch_parser import parse_prefetch
from ai_service.parsers.registry_parser import parse_all_registry

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NIST_IMAGE = PROJECT_ROOT / "data" / "test_images" / "SCHARDT.001"
PROD_DB = PROJECT_ROOT / "data" / "forensic.db"
CASE_ID = "TEST_NIST"

pytestmark = pytest.mark.skipif(
    not NIST_IMAGE.exists() or not PROD_DB.exists(),
    reason="NIST image or forensic.db missing",
)


@pytest.fixture(scope="module")
def mounted():
    img, fs = mount_image(str(NIST_IMAGE))
    yield img, fs
    img.close()


@pytest.fixture()
def parser_db(tmp_path, monkeypatch):
    """Temp DB with TEST_NIST files rows copied from the production index."""
    db_file = tmp_path / "parser_test.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    monkeypatch.setenv("FORENSIC_DB_PATH", str(db_file))
    initialise_db()
    conn = get_connection()

    prod = get_connection(str(PROD_DB))
    try:
        # Case row
        case = prod.execute(
            "SELECT case_id, name, image_path, created_at, status FROM cases WHERE case_id = ?",
            (CASE_ID,),
        ).fetchone()
        if case:
            conn.execute(
                """
                INSERT INTO cases (case_id, name, image_path, created_at, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    case["case_id"],
                    case["name"],
                    case["image_path"],
                    case["created_at"],
                    case["status"],
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO cases (case_id, name, image_path, created_at, status)
                VALUES (?, ?, ?, datetime('now'), 'mounted')
                """,
                (CASE_ID, "NIST", str(NIST_IMAGE)),
            )

        rows = prod.execute(
            """
            SELECT case_id, path, size, created, modified, accessed, extension, inode
            FROM files WHERE case_id = ?
            """,
            (CASE_ID,),
        ).fetchall()
        conn.executemany(
            """
            INSERT INTO files
                (case_id, path, size, created, modified, accessed, extension, inode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [tuple(r) for r in rows],
        )
        conn.commit()
    finally:
        prod.close()

    yield conn
    conn.close()


def test_registry_parser_populates_usb_device_history(mounted, parser_db):
    _, fs = mounted
    parse_all_registry(fs, CASE_ID, parser_db)

    usb_or_pcmcia = parser_db.execute(
        """
        SELECT COUNT(*) AS c FROM registry_entries
        WHERE case_id = ?
          AND (
            UPPER(key_path) LIKE '%USBSTOR%'
            OR key_path LIKE 'ControlSet001\\Enum\\USB%'
            OR UPPER(key_path) LIKE '%PCMCIA%'
          )
        """,
        (CASE_ID,),
    ).fetchone()["c"]
    assert usb_or_pcmcia > 0

    # Known NIST wireless PCMCIA card
    pcmcia = parser_db.execute(
        """
        SELECT COUNT(*) AS c FROM registry_entries
        WHERE case_id = ?
          AND (
            UPPER(value_data) LIKE '%WL110%'
            OR UPPER(key_path) LIKE '%WL110%'
          )
        """,
        (CASE_ID,),
    ).fetchone()["c"]
    assert pcmcia > 0

    stages = [
        r["stage_name"]
        for r in parser_db.execute(
            "SELECT stage_name FROM analysis_stages WHERE case_id = ?",
            (CASE_ID,),
        )
    ]
    assert "registry" in stages


def test_event_log_parser_populates_expected_ids(mounted, parser_db):
    _, fs = mounted
    parse_all_evtx(fs, CASE_ID, parser_db)

    total = parser_db.execute(
        "SELECT COUNT(*) AS c FROM event_logs WHERE case_id = ?",
        (CASE_ID,),
    ).fetchone()["c"]
    assert total > 0

    # Vista+ logon IDs and/or XP service/logon IDs
    expected = {4624, 4625, 528, 529, 7035, 7036, 7045}
    ids = {
        r["event_id"]
        for r in parser_db.execute(
            "SELECT DISTINCT event_id FROM event_logs WHERE case_id = ?",
            (CASE_ID,),
        )
    }
    assert ids & expected

    stages = [
        r["stage_name"]
        for r in parser_db.execute(
            "SELECT stage_name FROM analysis_stages WHERE case_id = ?",
            (CASE_ID,),
        )
    ]
    assert "events" in stages


def test_browser_parser_populates_history(mounted, parser_db):
    _, fs = mounted
    counts = parse_chrome_history(fs, CASE_ID, parser_db)
    assert sum(counts.values()) > 0

    total = parser_db.execute(
        "SELECT COUNT(*) AS c FROM browser_history WHERE case_id = ?",
        (CASE_ID,),
    ).fetchone()["c"]
    assert total > 0

    # SCHARDT uses IE
    browsers = {
        r["browser"]
        for r in parser_db.execute(
            "SELECT DISTINCT browser FROM browser_history WHERE case_id = ?",
            (CASE_ID,),
        )
    }
    assert browsers & {"ie", "chrome", "firefox"}

    stages = [
        r["stage_name"]
        for r in parser_db.execute(
            "SELECT stage_name FROM analysis_stages WHERE case_id = ?",
            (CASE_ID,),
        )
    ]
    assert "browser" in stages


def test_prefetch_parser_populates_known_tools(mounted, parser_db):
    _, fs = mounted
    result = parse_prefetch(fs, CASE_ID, parser_db)
    assert result["parsed"] > 0

    executables = {
        r["executable"].upper()
        for r in parser_db.execute(
            "SELECT executable FROM prefetch_entries WHERE case_id = ?",
            (CASE_ID,),
        )
    }
    assert "CAIN.EXE" in executables or "ETHEREAL.EXE" in executables
    assert "IEXPLORE.EXE" in executables

    stages = [
        r["stage_name"]
        for r in parser_db.execute(
            "SELECT stage_name FROM analysis_stages WHERE case_id = ?",
            (CASE_ID,),
        )
    ]
    assert "prefetch" in stages


def test_parsers_do_not_crash_on_missing_targets(parser_db):
    """Empty filesystem stub: parsers must complete without raising."""

    class _EmptyFS:
        def open(self, path):
            raise IOError("missing")

    # No matching files in DB beyond what we seeded — clear files to simulate miss
    parser_db.execute("DELETE FROM files WHERE case_id = ?", (CASE_ID,))
    parser_db.commit()

    fs = _EmptyFS()
    parse_all_registry(fs, CASE_ID, parser_db)
    parse_all_evtx(fs, CASE_ID, parser_db)
    parse_chrome_history(fs, CASE_ID, parser_db)
    parse_prefetch(fs, CASE_ID, parser_db)
