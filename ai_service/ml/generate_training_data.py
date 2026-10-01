"""Generate a synthetic labeled dataset anchored by the real NIST case features."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from ai_service.db.database import get_connection
from ai_service.ml.feature_engineer import FEATURE_NAMES, extract_features

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CSV = _PROJECT_ROOT / "data" / "training_data.csv"

RNG = np.random.default_rng(42)


def _clip_nonneg(arr: np.ndarray) -> np.ndarray:
    return np.maximum(arr, 0)


def _binary_noise(base: np.ndarray, flip_prob: float = 0.02) -> np.ndarray:
    """Rarely flip binary features to avoid perfect separability."""
    flips = RNG.random(base.shape) < flip_prob
    out = base.copy()
    out[flips] = 1 - out[flips]
    return out.astype(np.float64)


def _generate_normal(n: int = 400) -> pd.DataFrame:
    """Low-activity business-hours profiles — no malware / tor / odd logons."""
    data = {
        "failed_logon_count": _clip_nonneg(
            RNG.normal(0.5, 0.8, n)
        ).round().astype(int),
        "logon_outside_hours": np.zeros(n),
        "new_service_installed": (RNG.random(n) < 0.05).astype(float),
        "scheduled_task_created": (RNG.random(n) < 0.03).astype(float),
        "process_creation_count": _clip_nonneg(RNG.normal(5, 3, n)).round(),
        "unique_usb_devices": _clip_nonneg(RNG.normal(0.5, 0.7, n)).round(),
        "autorun_entries": _clip_nonneg(RNG.normal(2, 1.5, n)).round(),
        "tor_visits": np.zeros(n),
        "total_urls": _clip_nonneg(RNG.normal(40, 20, n)).round(),
        "known_malware_executed": np.zeros(n),
        "total_executions": _clip_nonneg(RNG.normal(25, 10, n)).round(),
        "sensitive_file_access": (RNG.random(n) < 0.08).astype(float),
    }
    # Soften binaries with tiny noise flips
    for col in (
        "logon_outside_hours",
        "new_service_installed",
        "scheduled_task_created",
        "tor_visits",
        "known_malware_executed",
        "sensitive_file_access",
    ):
        data[col] = _binary_noise(data[col], flip_prob=0.01)
        # Force malware/tor stay near zero for normals
        if col in ("known_malware_executed", "tor_visits", "logon_outside_hours"):
            data[col] = np.zeros(n)

    df = pd.DataFrame(data)[FEATURE_NAMES]
    # Add gaussian noise to continuous-ish columns then re-clip
    for col in (
        "failed_logon_count",
        "process_creation_count",
        "unique_usb_devices",
        "autorun_entries",
        "total_urls",
        "total_executions",
    ):
        df[col] = _clip_nonneg(df[col] + RNG.normal(0, 0.3, n)).round()
    df["label"] = 0
    return df


def _generate_suspicious(n: int = 300) -> pd.DataFrame:
    """Varied hostile profiles — malware, off-hours, USB, tor, tasks, etc."""
    data = {
        "failed_logon_count": _clip_nonneg(RNG.normal(12, 8, n)).round(),
        "logon_outside_hours": (RNG.random(n) < 0.75).astype(float),
        "new_service_installed": (RNG.random(n) < 0.65).astype(float),
        "scheduled_task_created": (RNG.random(n) < 0.55).astype(float),
        "process_creation_count": _clip_nonneg(RNG.normal(80, 40, n)).round(),
        "unique_usb_devices": _clip_nonneg(RNG.normal(4, 2.5, n)).round(),
        "autorun_entries": _clip_nonneg(RNG.normal(8, 4, n)).round(),
        "tor_visits": (RNG.random(n) < 0.45).astype(float),
        "total_urls": _clip_nonneg(RNG.normal(150, 60, n)).round(),
        "known_malware_executed": (RNG.random(n) < 0.85).astype(float),
        "total_executions": _clip_nonneg(RNG.normal(90, 35, n)).round(),
        "sensitive_file_access": (RNG.random(n) < 0.7).astype(float),
    }
    df = pd.DataFrame(data)[FEATURE_NAMES]
    for col in (
        "failed_logon_count",
        "process_creation_count",
        "unique_usb_devices",
        "autorun_entries",
        "total_urls",
        "total_executions",
    ):
        df[col] = _clip_nonneg(df[col] + RNG.normal(0, 1.0, n)).round()
    # Ensure every suspicious row has at least one strong signal
    strong = (
        (df["known_malware_executed"] > 0)
        | (df["tor_visits"] > 0)
        | (df["failed_logon_count"] >= 5)
        | (df["logon_outside_hours"] > 0)
        | (df["scheduled_task_created"] > 0)
    )
    df.loc[~strong, "known_malware_executed"] = 1.0
    df["label"] = 1
    return df


def generate_dataset(
    nist_case_id: str,
    conn,
    csv_path: str | Path | None = None,
) -> pd.DataFrame:
    """Build 400 normal + 300 suspicious + 1 NIST anchor row; save CSV."""
    csv_path = Path(csv_path) if csv_path else DEFAULT_CSV
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    normal = _generate_normal(400)
    suspicious = _generate_suspicious(300)

    nist_features = extract_features(nist_case_id, conn)
    nist_row = {name: float(nist_features[name]) for name in FEATURE_NAMES}
    nist_row["label"] = 1
    nist_df = pd.DataFrame([nist_row])

    df = pd.concat([normal, suspicious, nist_df], ignore_index=True)
    # Stable column order
    df = df[FEATURE_NAMES + ["label"]]
    df.to_csv(csv_path, index=False)
    return df


if __name__ == "__main__":
    conn = get_connection()
    try:
        frame = generate_dataset("TEST_NIST", conn)
        print(f"Wrote {DEFAULT_CSV} shape={frame.shape}")
        print(frame["label"].value_counts().to_dict())
        print(frame.tail(1)[FEATURE_NAMES].to_dict(orient="records")[0])
    finally:
        conn.close()
