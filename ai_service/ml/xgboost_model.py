"""XGBoost supervised threat classifier — train once, load for inference."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from ai_service.ml.feature_engineer import FEATURE_NAMES

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = _PROJECT_ROOT / "models" / "xgboost_model.json"
DEFAULT_CSV = _PROJECT_ROOT / "data" / "training_data.csv"

# Loaded once at agent init (lazy); reused across requests.
_MODEL: Optional[XGBClassifier] = None
_MODEL_PATH: Optional[Path] = None


def train_xgboost(
    csv_path: Union[str, Path] = DEFAULT_CSV,
    model_path: Union[str, Path] = DEFAULT_MODEL_PATH,
) -> float:
    """Train XGBClassifier, print metrics, save JSON. Returns AUC-ROC."""
    global _MODEL, _MODEL_PATH

    csv_path = Path(csv_path)
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv_path)
    X = df[FEATURE_NAMES].astype(float)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
    )
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    preds = (proba >= 0.5).astype(int)
    auc = float(roc_auc_score(y_test, proba))

    print(f"AUC-ROC: {auc:.4f}")
    print(classification_report(y_test, preds, digits=4))
    if auc < 0.75:
        print(
            "WARNING: AUC-ROC below 0.75 — consider adding more varied "
            "suspicious training samples."
        )
    elif auc < 0.80:
        print("WARNING: AUC-ROC below target 0.80 (acceptable if >= 0.75).")

    model.save_model(str(model_path))
    print(f"Saved model to {model_path}")

    _MODEL = model
    _MODEL_PATH = model_path
    return auc


def load_model(model_path: Union[str, Path] = DEFAULT_MODEL_PATH) -> XGBClassifier:
    """Load the XGBoost model from disk (cached in-process)."""
    global _MODEL, _MODEL_PATH
    model_path = Path(model_path)
    if _MODEL is not None and _MODEL_PATH == model_path:
        return _MODEL
    model = XGBClassifier()
    model.load_model(str(model_path))
    _MODEL = model
    _MODEL_PATH = model_path
    return model


def predict_threat(
    feature_vector: np.ndarray,
    model_path: Union[str, Path] = DEFAULT_MODEL_PATH,
) -> float:
    """Return P(suspicious) for a 12-feature vector."""
    model = load_model(model_path)
    vec = np.asarray(feature_vector, dtype=np.float64).reshape(1, -1)
    # Use DataFrame so feature names match training
    frame = pd.DataFrame(vec, columns=FEATURE_NAMES)
    return float(model.predict_proba(frame)[0, 1])


if __name__ == "__main__":
    from ai_service.db.database import get_connection
    from ai_service.ml.feature_engineer import extract_features, features_to_vector

    auc = train_xgboost()
    conn = get_connection()
    try:
        feats = extract_features("TEST_NIST", conn)
        score = predict_threat(features_to_vector(feats))
        print(f"NIST threat probability: {score:.4f}")
        print(f"NIST suspicious (xgb>0.6): {score > 0.6}")
    finally:
        conn.close()
    print(f"Final AUC: {auc:.4f}")
