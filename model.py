from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .config import ModelConfig


FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "pps",
    "bps",
    "avg_packet_len",
    "std_packet_len",
    "syn_ratio",
    "fin_ratio",
    "ack_ratio",
    "avg_inter_arrival",
    "protocol_tcp",
    "protocol_udp",
]


@dataclass(slots=True)
class PredictionResult:
    label: str
    score: float
    metadata: Dict[str, float | str]


class ModelManager:
    def __init__(self, config: ModelConfig):
        self.config = config
        self.model_path = self.config.artifact_dir / "isolation_forest.joblib"
        self.pipeline: Pipeline | None = None

    def load_or_train(self) -> None:
        if self.model_path.exists():
            self.pipeline = joblib.load(self.model_path)
            return
        data = self._load_baseline()
        self.pipeline = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "model",
                    IsolationForest(
                        contamination=self.config.contamination,
                        n_estimators=200,
                        random_state=42,
                        n_jobs=-1,
                    ),
                ),
            ]
        )
        self.pipeline.fit(data)
        joblib.dump(self.pipeline, self.model_path)

    def predict(self, features: Dict[str, float], metadata: Dict[str, float | str]) -> PredictionResult:
        if not self.pipeline:
            raise RuntimeError("Model pipeline is not initialized. Call load_or_train() first.")
        vector = np.array([[features.get(col, 0.0) for col in FEATURE_COLUMNS]])
        score = float(self.pipeline.decision_function(vector)[0])
        label = "malicious" if score < self.config.anomaly_threshold else "benign"
        return PredictionResult(label=label, score=score, metadata=metadata)

    def _load_baseline(self) -> pd.DataFrame:
        if self.config.baseline_path and self.config.baseline_path.exists():
            df = pd.read_csv(self.config.baseline_path)
        else:
            df = self._generate_synthetic_baseline()
        missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
        if missing:
            raise ValueError(f"Baseline dataset missing columns: {missing}")
        return df[FEATURE_COLUMNS]

    def _generate_synthetic_baseline(self, samples: int = 1500) -> pd.DataFrame:
        rng = np.random.default_rng(42)

        data = {
            "packet_count": rng.poisson(lam=20, size=samples) + 1,
            "byte_count": rng.poisson(lam=12000, size=samples) + 500,
            "duration": rng.uniform(0.5, 10.0, size=samples),
            "avg_packet_len": rng.normal(400, 120, size=samples).clip(60, 1500),
            "std_packet_len": rng.uniform(5, 200, size=samples),
            "syn_ratio": rng.uniform(0.0, 0.2, size=samples),
            "fin_ratio": rng.uniform(0.0, 0.1, size=samples),
            "ack_ratio": rng.uniform(0.2, 0.8, size=samples),
            "avg_inter_arrival": rng.uniform(0.001, 0.2, size=samples),
            "protocol_tcp": rng.choice([0, 1], size=samples, p=[0.3, 0.7]),
        }
        data["protocol_udp"] = 1 - data["protocol_tcp"]
        data["pps"] = data["packet_count"] / data["duration"]
        data["bps"] = data["byte_count"] * 8 / data["duration"]
        return pd.DataFrame(data)

