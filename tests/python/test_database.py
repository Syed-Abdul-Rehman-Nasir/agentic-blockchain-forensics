"""Tests for ai_service.db.database — uses a temp DB, never the production file."""

from __future__ import annotations

import sqlite3

import pytest

import ai_service.db.database as database
from ai_service.db.database import (
    create_case,
    get_artifacts_for_case,
    get_case,
    get_completed_stages,
    get_connection,
    initialise_db,
    list_cases,
    log_audit,
    mark_stage_complete,
    update_case_hashes,
)


EXPECTED_TABLES = {
    "cases",
    "files",
    "registry_entries",
    "event_logs",
    "browser_history",
    "prefetch_entries",
    "artifacts",
    "analysis_stages",
    "audit_log",
}


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Point DB_PATH at an isolated tempfile for each test."""
    db_file = tmp_path / "test_forensic.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    monkeypatch.setenv("FORENSIC_DB_PATH", str(db_file))
    initialise_db()
    conn = get_connection()
    yield conn
    conn.close()


def test_initialise_db_creates_all_tables(temp_db):
    rows = temp_db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    names = {row["name"] for row in rows}
    assert EXPECTED_TABLES.issubset(names)
    assert len(EXPECTED_TABLES) == 9


def test_create_case_inserts_and_retrieves(temp_db):
    create_case("CASE001", "Test Case", "/path/to/image.E01", conn=temp_db)
    row = temp_db.execute(
        "SELECT * FROM cases WHERE case_id = ?", ("CASE001",)
    ).fetchone()
    assert row is not None
    assert row["name"] == "Test Case"
    assert row["image_path"] == "/path/to/image.E01"
    assert row["status"] == "pending"
    assert row["created_at"] is not None


def test_update_case_hashes(temp_db):
    create_case("CASE002", "Hash Case", "/img.E01", conn=temp_db)
    update_case_hashes(
        "CASE002",
        acquisition_hash="abc123md5",
        system_hash="def456sha256",
        conn=temp_db,
    )
    row = temp_db.execute(
        "SELECT acquisition_hash, system_hash FROM cases WHERE case_id = ?",
        ("CASE002",),
    ).fetchone()
    assert row["acquisition_hash"] == "abc123md5"
    assert row["system_hash"] == "def456sha256"


def test_mark_stage_complete_and_get_completed_stages(temp_db):
    create_case("CASE003", "Stage Case", "/img.E01", conn=temp_db)
    mark_stage_complete("CASE003", "disk_mount", conn=temp_db)
    mark_stage_complete("CASE003", "registry", conn=temp_db)
    stages = get_completed_stages("CASE003", conn=temp_db)
    assert "disk_mount" in stages
    assert "registry" in stages
    assert len(stages) == 2


def test_wal_mode_active(temp_db):
    mode = temp_db.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"


def test_get_case_returns_dict_or_none(temp_db):
    create_case("CASE_GET", "Lookup", "/img.E01", conn=temp_db)
    found = get_case("CASE_GET", conn=temp_db)
    assert found is not None
    assert found["case_id"] == "CASE_GET"
    assert found["name"] == "Lookup"
    assert get_case("MISSING", conn=temp_db) is None


def test_list_cases_orders_newest_first(temp_db):
    create_case("CASE_OLD", "Old", "/old.E01", conn=temp_db)
    create_case("CASE_NEW", "New", "/new.E01", conn=temp_db)
    temp_db.execute(
        "UPDATE cases SET created_at = ? WHERE case_id = ?",
        ("2020-01-01T00:00:00+00:00", "CASE_OLD"),
    )
    temp_db.execute(
        "UPDATE cases SET created_at = ? WHERE case_id = ?",
        ("2024-01-01T00:00:00+00:00", "CASE_NEW"),
    )
    temp_db.commit()
    cases = list_cases(conn=temp_db)
    assert [c["case_id"] for c in cases[:2]] == ["CASE_NEW", "CASE_OLD"]


def test_log_audit_appends_row(temp_db):
    create_case("CASE_AUDIT", "Audit", "/img.E01", conn=temp_db)
    log_audit("CASE_AUDIT", "unit_test", "persisted action", conn=temp_db)
    row = temp_db.execute(
        "SELECT action, details FROM audit_log WHERE case_id = ?",
        ("CASE_AUDIT",),
    ).fetchone()
    assert row["action"] == "unit_test"
    assert row["details"] == "persisted action"


def test_get_artifacts_for_case_returns_counts(temp_db):
    create_case("CASE_ART", "Artifacts", "/img.E01", conn=temp_db)
    temp_db.execute(
        "INSERT INTO files (case_id, path, size) VALUES (?, ?, ?)",
        ("CASE_ART", "/WINDOWS/system32/cmd.exe", 100),
    )
    temp_db.execute(
        """
        INSERT INTO registry_entries (case_id, hive, key_path, value_name, value_data)
        VALUES (?, 'SYSTEM', 'ControlSet001\\\\Enum\\\\USB', 'DeviceDesc', 'Hub')
        """,
        ("CASE_ART",),
    )
    temp_db.commit()
    payload = get_artifacts_for_case("CASE_ART", conn=temp_db)
    assert payload["file_count"] == 1
    assert payload["registry_count"] == 1
    assert payload["counts"]["files"] == 1
    assert len(payload["registry"]) == 1
