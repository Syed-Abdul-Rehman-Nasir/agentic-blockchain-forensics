"""ThreatInterpretationAgent — ML-based threat scoring agent.

Committee note: this agent is genuinely distinct from ArtifactAnalysisAgent.
ArtifactAnalysisAgent extracts forensic evidence (parsers / pytsk3).
ThreatInterpretationAgent only scores that evidence with XGBoost + autoencoder
and never mounts disk images or parses hives. Different domain, inputs, outputs.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from ai_service.agents.base_agent import BaseAgent
from ai_service.db.database import get_connection
from ai_service.ml.autoencoder import load_autoencoder, score_anomaly
from ai_service.ml.feature_engineer import extract_features, features_to_vector
from ai_service.ml.xgboost_model import load_model, predict_threat


class ThreatInterpretationAgent(BaseAgent):
    """Threat Agent: supervised + unsupervised scoring over the 12-feature vector."""

    def __init__(self) -> None:
        # Load both models once at agent init — not per request (project rule).
        load_model()
        load_autoencoder()

    def analyse(self, case_id: str, conn=None) -> Dict[str, Any]:
        owns = conn is None
        if owns:
            conn = get_connection()

        try:
            self.log_action(
                case_id,
                "threat_analysis_started",
                "Scoring case with XGBoost + autoencoder",
                conn=conn,
            )

            features = extract_features(case_id, conn)
            vector = features_to_vector(features)
            xgboost_score = float(predict_threat(vector))
            autoencoder_score, is_anomaly = score_anomaly(vector)
            autoencoder_score = float(autoencoder_score)
            flagged = bool(xgboost_score > 0.6 or is_anomaly)

            conn.execute(
                """
                INSERT INTO artifacts
                    (case_id, artifact_type, data_json, xgboost_score,
                     autoencoder_score, flagged)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    "threat_assessment",
                    json.dumps(dict(features)),
                    xgboost_score,
                    autoencoder_score,
                    1 if flagged else 0,
                ),
            )
            conn.commit()

            self.mark_stage_complete(case_id, "threat_analysis", conn=conn)
            self.log_action(
                case_id,
                "threat_analysis_completed",
                (
                    f"flagged={flagged} xgboost={xgboost_score:.4f} "
                    f"autoencoder={autoencoder_score:.6f} anomaly={is_anomaly}"
                ),
                conn=conn,
            )

            return {
                "xgboost_score": xgboost_score,
                "autoencoder_score": autoencoder_score,
                "autoencoder_anomaly": bool(is_anomaly),
                "flagged": flagged,
                "features": dict(features),
            }
        finally:
            if owns:
                conn.close()
