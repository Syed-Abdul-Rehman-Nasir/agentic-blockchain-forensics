"""Offline threat-agent checkpoint resume tests (no NIST image required)."""

from __future__ import annotations

import json
from unittest.mock import patch

from ai_service.agents.threat_agent import ThreatInterpretationAgent
from ai_service.db.database import (
    create_case,
    get_connection,
    initialise_db,
    mark_stage_complete,
)
import ai_service.db.database as database


def test_threat_agent_checkpoint_resume_skips_rescore(tmp_path, monkeypatch):
    """Completed threat_analysis must return the stored assessment without re-scoring."""
    db_file = tmp_path / "threat_resume.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_file))
    monkeypatch.setenv("FORENSIC_DB_PATH", str(db_file))
    initialise_db()
    conn = get_connection()
    create_case("THREAT_RESUME", "Threat Resume", "/tmp/fake.E01", conn=conn)
    features = {"known_malware_executed": 1.0, "failed_logon_count": 2.0}
    conn.execute(
        """
        INSERT INTO artifacts
            (case_id, artifact_type, data_json, xgboost_score, autoencoder_score, flagged)
        VALUES (?, 'threat_assessment', ?, 0.91, 12.5, 1)
        """,
        ("THREAT_RESUME", json.dumps(features)),
    )
    mark_stage_complete("THREAT_RESUME", "threat_analysis", conn=conn)
    conn.commit()

    with patch(
        "ai_service.agents.threat_agent.extract_features",
        side_effect=AssertionError("extract_features must not run on resume"),
    ), patch(
        "ai_service.agents.threat_agent.predict_threat",
        side_effect=AssertionError("predict_threat must not run on resume"),
    ):
        agent = ThreatInterpretationAgent()
        result = agent.analyse("THREAT_RESUME", conn=conn)

    assert result["resumed"] is True
    assert result["xgboost_score"] == 0.91
    assert result["autoencoder_score"] == 12.5
    assert result["flagged"] is True
    assert result["features"]["known_malware_executed"] == 1.0

    count = conn.execute(
        """
        SELECT COUNT(*) AS c FROM artifacts
        WHERE case_id = ? AND artifact_type = 'threat_assessment'
        """,
        ("THREAT_RESUME",),
    ).fetchone()["c"]
    assert count == 1
    conn.close()
