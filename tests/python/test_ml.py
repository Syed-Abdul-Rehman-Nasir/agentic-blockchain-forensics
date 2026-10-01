"""Phase 3 ML tests — feature engineering, training data, XGBoost, autoencoder."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
import torch

from ai_service.db.database import get_connection
from ai_service.ml.autoencoder import score_anomaly, train_autoencoder
from ai_service.ml.feature_engineer import (
    FEATURE_NAMES,
    extract_features,
    features_to_vector,
)
from ai_service.ml.generate_training_data import generate_dataset
from ai_service.ml.xgboost_model import predict_threat, train_xgboost

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROD_DB = PROJECT_ROOT / "data" / "forensic.db"
CASE_ID = "TEST_NIST"

pytestmark = pytest.mark.skipif(
    not PROD_DB.exists(),
    reason="forensic.db missing — run Phase 1/2 ingest first",
)


@pytest.fixture(scope="module")
def nist_features():
    conn = get_connection(str(PROD_DB))
    try:
        feats = extract_features(CASE_ID, conn)
        yield feats
    finally:
        conn.close()


@pytest.fixture(scope="module")
def trained_artifacts(tmp_path_factory):
    """Generate CSV + train both models once under a temp models dir."""
    root = tmp_path_factory.mktemp("ml")
    csv_path = root / "training_data.csv"
    xgb_path = root / "xgboost_model.json"
    ae_path = root / "autoencoder.pt"

    conn = get_connection(str(PROD_DB))
    try:
        df = generate_dataset(CASE_ID, conn, csv_path=csv_path)
    finally:
        conn.close()

    auc = train_xgboost(csv_path=csv_path, model_path=xgb_path)
    threshold = train_autoencoder(csv_path=csv_path, model_path=ae_path, epochs=50)

    return {
        "csv": csv_path,
        "xgb": xgb_path,
        "ae": ae_path,
        "df": df,
        "auc": auc,
        "threshold": threshold,
    }


def test_feature_engineering_returns_12_features(nist_features):
    assert list(nist_features.keys()) == FEATURE_NAMES
    assert len(nist_features) == 12
    vec = features_to_vector(nist_features)
    assert vec.shape == (12,)
    assert nist_features["known_malware_executed"] == 1.0
    assert nist_features["total_executions"] > 0
    assert nist_features["total_urls"] > 0


def test_training_data_has_701_rows(trained_artifacts):
    df = trained_artifacts["df"]
    assert len(df) == 701
    assert list(df.columns) == FEATURE_NAMES + ["label"]
    assert set(df["label"].unique()) <= {0, 1}
    assert (df["label"] == 0).sum() == 400
    assert (df["label"] == 1).sum() == 301


def test_xgboost_auc_and_nist_score(nist_features, trained_artifacts):
    auc = trained_artifacts["auc"]
    assert auc >= 0.80
    score = predict_threat(
        features_to_vector(nist_features),
        model_path=trained_artifacts["xgb"],
    )
    assert 0.0 <= score <= 1.0
    assert score > 0.6


def test_autoencoder_trains_and_scores(nist_features, trained_artifacts):
    assert trained_artifacts["ae"].exists()
    assert trained_artifacts["threshold"] > 0
    error, is_anomaly = score_anomaly(
        features_to_vector(nist_features),
        model_path=trained_artifacts["ae"],
    )
    assert isinstance(error, float)
    assert error >= 0
    assert isinstance(is_anomaly, (bool, np.bool_))


def test_models_reload_from_disk(nist_features, trained_artifacts):
    # Clear module caches by loading via path explicitly after re-import pattern
    import ai_service.ml.xgboost_model as xgb_mod
    import ai_service.ml.autoencoder as ae_mod

    xgb_mod._MODEL = None
    xgb_mod._MODEL_PATH = None
    ae_mod._MODEL = None
    ae_mod._CHECKPOINT = None
    ae_mod._CHECKPOINT_PATH = None

    score = predict_threat(
        features_to_vector(nist_features),
        model_path=trained_artifacts["xgb"],
    )
    error, is_anomaly = score_anomaly(
        features_to_vector(nist_features),
        model_path=trained_artifacts["ae"],
    )
    assert 0.0 <= score <= 1.0
    assert error >= 0


def test_nist_scores_as_suspicious(nist_features, trained_artifacts):
    score = predict_threat(
        features_to_vector(nist_features),
        model_path=trained_artifacts["xgb"],
    )
    error, is_anomaly = score_anomaly(
        features_to_vector(nist_features),
        model_path=trained_artifacts["ae"],
    )
    suspicious = score > 0.6 or bool(is_anomaly)
    assert suspicious, f"NIST not suspicious: xgb={score}, anomaly={is_anomaly}, err={error}"


def test_cuda_available_for_autoencoder():
    # Gate expects CUDA on the build machine; fail loudly if missing.
    assert torch.cuda.is_available(), "CUDA required for Phase 3 gate on this machine"
