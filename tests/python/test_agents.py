"""Phase 4 agent / LangGraph / ChromaDB tests against TEST_NIST."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from ai_service.agents.artifact_agent import ArtifactAnalysisAgent
from ai_service.agents.threat_agent import ThreatInterpretationAgent
from ai_service.db.database import (
    create_case,
    get_completed_stages,
    get_connection,
    initialise_db,
    mark_stage_complete,
)
from ai_service.graph.forensic_graph import run_analysis, run_query
from ai_service.rag.vector_store import VectorStore

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NIST_IMAGE = PROJECT_ROOT / "data" / "test_images" / "SCHARDT.001"
PROD_DB = PROJECT_ROOT / "data" / "forensic.db"
CASE_ID = "TEST_NIST"

pytestmark = pytest.mark.skipif(
    not NIST_IMAGE.exists() or not PROD_DB.exists(),
    reason="NIST image or forensic.db missing",
)


@pytest.fixture(scope="module")
def threat_agent():
    return ThreatInterpretationAgent()


@pytest.fixture(scope="module")
def vector_store(tmp_path_factory):
    chroma = tmp_path_factory.mktemp("chroma")
    return VectorStore(chroma_path=str(chroma))


def test_artifact_agent_populates_tables_on_nist():
    agent = ArtifactAnalysisAgent()
    summary = agent.analyse(CASE_ID, str(NIST_IMAGE))
    assert summary["file_count"] > 1000
    assert summary["registry_count"] > 0
    assert summary["event_count"] > 0
    assert summary["browser_count"] > 0
    assert summary["prefetch_count"] > 0
    assert summary["hashes"]["system_hash"]


def test_artifact_agent_checkpoint_resume_skips_ingest(tmp_path, monkeypatch):
    """If disk_mount is complete, ingest_e01 must not be called."""
    import ai_service.db.database as database

    db_file = tmp_path / "resume.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    monkeypatch.setenv("FORENSIC_DB_PATH", str(db_file))
    initialise_db()
    conn = get_connection()
    create_case("RESUME_CASE", "Resume", str(NIST_IMAGE), conn=conn)
    mark_stage_complete("RESUME_CASE", "disk_mount", conn=conn)
    # Seed minimal files so counts work; parsers may no-op without paths
    conn.execute(
        """
        INSERT INTO files (case_id, path, size, extension)
        VALUES (?, '/WINDOWS/system32/config/system', 100, NULL)
        """,
        ("RESUME_CASE",),
    )
    conn.commit()

    called = {"ingest": False}

    def _boom(*args, **kwargs):
        called["ingest"] = True
        raise AssertionError("ingest_e01 should not run when disk_mount complete")

    agent = ArtifactAnalysisAgent()
    with patch(
        "ai_service.agents.artifact_agent.ingest_e01", side_effect=_boom
    ), patch(
        "ai_service.agents.artifact_agent.mount_image",
        side_effect=RuntimeError("stop before parsers — resume path verified"),
    ):
        try:
            agent.analyse("RESUME_CASE", str(NIST_IMAGE), conn=conn)
        except RuntimeError as exc:
            assert "stop before parsers" in str(exc)

    assert called["ingest"] is False
    conn.close()


def test_threat_agent_flags_nist(threat_agent):
    result = threat_agent.analyse(CASE_ID)
    assert 0.0 <= result["xgboost_score"] <= 1.0
    assert result["flagged"] is True
    assert result["features"]["known_malware_executed"] == 1.0
    stages = get_completed_stages(CASE_ID)
    assert "threat_analysis" in stages


def test_vector_store_index_and_query(vector_store):
    info = vector_store.index_case(CASE_ID)
    assert info["indexed"] > 0
    # Never index raw files — only artifact types
    sample = vector_store.query(CASE_ID, "Cain Ethereal password sniffer", n_results=8)
    assert sample["results"]
    types = {r["metadata"].get("type") for r in sample["results"]}
    assert types <= {"event_log", "registry", "browser", "prefetch"}
    joined = " ".join(r["document"] or "" for r in sample["results"]).upper()
    assert "CAIN" in joined or "ETHEREAL" in joined or "PREFETCH" in types


def test_langgraph_run_analysis_end_to_end():
    state = run_analysis(CASE_ID, str(NIST_IMAGE))
    assert state.get("errors") in ([], None) or state["errors"] == []
    assert state["artifact_summary"]["file_count"] > 0
    assert state["threat_scores"]["flagged"] is True
    assert "threat_analysis" in state["completed_stages"]
    assert "rag_indexing" in state["completed_stages"]
    assert state.get("index_summary", {}).get("indexed", 0) > 0


def test_langgraph_run_query_stub():
    state = run_query(CASE_ID, "What malware tools were executed?")
    assert state.get("query_response")
    resp = state["query_response"]
    assert resp.get("status") in ("ok", "error", "stub")
    if resp.get("status") == "ok":
        assert resp.get("answer")
