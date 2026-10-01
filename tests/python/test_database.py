"""Tests for ai_service.db.database — uses a temp DB, never the production file."""

from __future__ import annotations

import sqlite3

import pytest

import ai_service.db.database as database
from ai_service.db.database import (
    create_case,
    get_completed_stages,
    get_connection,
    initialise_db,
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
