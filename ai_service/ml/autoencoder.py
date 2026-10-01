"""PyTorch autoencoder anomaly detector — trained on normal samples only.

Anomaly = reconstruction error above mean + 2*std of normal training errors.
Models load once and reuse the checkpoint (threshold + scaler stats included).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple, Union

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from ai_service.ml.feature_engineer import FEATURE_NAMES

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = _PROJECT_ROOT / "models" / "autoencoder.pt"
DEFAULT_CSV = _PROJECT_ROOT / "data" / "training_data.csv"

_CHECKPOINT: Optional[dict] = None
_CHECKPOINT_PATH: Optional[Path] = None
_MODEL: Optional["ThreatAutoencoder"] = None
_DEVICE: Optional[torch.device] = None


class ThreatAutoencoder(nn.Module):
    """12 → 8 → 4 → 8 → 12 reconstruction network."""

    def __init__(self, input_dim: int = 12):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 8),
            nn.ReLU(),
            nn.Linear(8, 4),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


def _get_device() -> torch.device:
    # Conditional device selection keeps the code portable (project rule).
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _scale(X: np.ndarray, mean: np.ndarray, scale: np.ndarray) -> np.ndarray:
    scale_safe = np.where(scale == 0, 1.0, scale)
    return (X - mean) / scale_safe


def train_autoencoder(
    csv_path: Union[str, Path] = DEFAULT_CSV,
    model_path: Union[str, Path] = DEFAULT_MODEL_PATH,
    epochs: int = 100,
) -> float:
    """Train on normal rows only; save checkpoint with threshold + scaler."""
    global _CHECKPOINT, _CHECKPOINT_PATH, _MODEL, _DEVICE

    csv_path = Path(csv_path)
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv_path)
    normal = df[df["label"] == 0][FEATURE_NAMES].astype(float).to_numpy()
    if len(normal) == 0:
        raise ValueError("No normal samples available for autoencoder training")

    mean = normal.mean(axis=0)
    scale = normal.std(axis=0)
    scale = np.where(scale == 0, 1.0, scale)
    X_scaled = _scale(normal, mean, scale)

    device = _get_device()
    print(f"Autoencoder training device: {device}")

    model = ThreatAutoencoder(input_dim=len(FEATURE_NAMES)).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.MSELoss()

    tensor = torch.tensor(X_scaled, dtype=torch.float32)
    loader = DataLoader(TensorDataset(tensor, tensor), batch_size=32, shuffle=True)

    model.train()
    for epoch in range(epochs):
        total_loss = 0.0
        batches = 0
        for batch_x, _ in loader:
            batch_x = batch_x.to(device)
            optimizer.zero_grad()
            recon = model(batch_x)
            loss = criterion(recon, batch_x)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item())
            batches += 1
        if (epoch + 1) % 20 == 0 or epoch == 0:
            print(f"epoch {epoch + 1}/{epochs} loss={total_loss / max(batches, 1):.6f}")

    # Reconstruction errors on all normal samples → threshold
    model.eval()
    with torch.no_grad():
        recon = model(tensor.to(device)).cpu().numpy()
    errors = np.mean((X_scaled - recon) ** 2, axis=1)
    threshold = float(errors.mean() + 2.0 * errors.std())
    print(f"Anomaly threshold (mean+2*std): {threshold:.6f}")

    checkpoint = {
        "model_state": model.cpu().state_dict(),
        "threshold": threshold,
        "input_dim": len(FEATURE_NAMES),
        "scaler_mean": mean.astype(np.float64),
        "scaler_scale": scale.astype(np.float64),
    }
    torch.save(checkpoint, model_path)
    print(f"Saved checkpoint to {model_path}")

    _CHECKPOINT = checkpoint
    _CHECKPOINT_PATH = model_path
    _MODEL = model
    _DEVICE = device
    # Keep model on device for subsequent scoring in this process
    _MODEL.to(device)
    return threshold


def load_autoencoder(
    model_path: Union[str, Path] = DEFAULT_MODEL_PATH,
) -> Tuple[ThreatAutoencoder, dict, torch.device]:
    """Load checkpoint once; return model, checkpoint dict, device."""
    global _CHECKPOINT, _CHECKPOINT_PATH, _MODEL, _DEVICE

    model_path = Path(model_path)
    if (
        _MODEL is not None
        and _CHECKPOINT is not None
        and _CHECKPOINT_PATH == model_path
    ):
        return _MODEL, _CHECKPOINT, _DEVICE or _get_device()

    # weights_only=False needed for numpy arrays in checkpoint (PyTorch 2.6+)
    try:
        checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
    except TypeError:
        checkpoint = torch.load(model_path, map_location="cpu")

    device = _get_device()
    model = ThreatAutoencoder(input_dim=int(checkpoint["input_dim"]))
    model.load_state_dict(checkpoint["model_state"])
    model.to(device)
    model.eval()

    _CHECKPOINT = checkpoint
    _CHECKPOINT_PATH = model_path
    _MODEL = model
    _DEVICE = device
    return model, checkpoint, device


def score_anomaly(
    feature_vector: np.ndarray,
    model_path: Union[str, Path] = DEFAULT_MODEL_PATH,
) -> Tuple[float, bool]:
    """Return (reconstruction_error, is_anomaly) for a 12-feature vector."""
    model, checkpoint, device = load_autoencoder(model_path)
    mean = np.asarray(checkpoint["scaler_mean"], dtype=np.float64)
    scale = np.asarray(checkpoint["scaler_scale"], dtype=np.float64)
    threshold = float(checkpoint["threshold"])

    vec = np.asarray(feature_vector, dtype=np.float64).reshape(1, -1)
    scaled = _scale(vec, mean, scale)
    tensor = torch.tensor(scaled, dtype=torch.float32, device=device)

    model.eval()
    with torch.no_grad():
        recon = model(tensor).cpu().numpy()
    error = float(np.mean((scaled - recon) ** 2))
    return error, error > threshold


if __name__ == "__main__":
    from ai_service.db.database import get_connection
    from ai_service.ml.feature_engineer import extract_features, features_to_vector

    thr = train_autoencoder()
    conn = get_connection()
    try:
        feats = extract_features("TEST_NIST", conn)
        err, is_anom = score_anomaly(features_to_vector(feats))
        print(f"NIST reconstruction error: {err:.6f}")
        print(f"NIST is_anomaly: {is_anom}")
        print(f"Threshold: {thr:.6f}")
    finally:
        conn.close()
