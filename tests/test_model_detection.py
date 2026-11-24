import random

import pytest

from src.config import ModelConfig
from src.feature_engineer import FeatureEngineer
from src.model import ModelManager
from src.traffic import ATTACKS, benign_flow


@pytest.fixture(scope="module")
def model(tmp_path_factory):
    manager = ModelManager(ModelConfig(artifact_dir=tmp_path_factory.mktemp("artifacts")))
    manager.load_or_train()
    return manager


def labels_for(model, packets):
    engineer = FeatureEngineer(flow_timeout_s=5, max_flows=5000, min_packets=5)
    results = []
    for pkt in sorted(packets, key=lambda p: p.timestamp):
        results += engineer.process_packet(pkt)
    results += engineer.flush()
    return [model.predict(r["features"], r["metadata"]).label for r in results]


def test_benign_false_alarm_rate_is_low(model):
    rng = random.Random(7)
    packets = [p for i in range(300) for p in benign_flow(rng, i * 0.05, i)]
    labels = labels_for(model, packets)
    assert len(labels) == 300
    assert labels.count("malicious") / len(labels) <= 0.03


@pytest.mark.parametrize("name", ["SYN flood", "bulk exfiltration", "UDP flood"])
def test_volumetric_attacks_are_detected(model, name):
    rng = random.Random(11)
    detected = sum("malicious" in labels_for(model, ATTACKS[name](rng, 0.0, i)) for i in range(25))
    assert detected == 25


def test_slow_port_scan_is_a_known_blind_spot(model):
    # Each probe is a separate one-packet flow, so no flow is long enough to be scored.
    # This test documents the limitation. If it ever fails, detection improved: update the README.
    assert labels_for(model, ATTACKS["port scan"](random.Random(3), 0.0, 1)) == []


def test_model_creates_its_artifact_directory_and_can_train_from_a_csv(tmp_path):
    import pandas as pd

    from src.model import FEATURE_COLUMNS

    rng = random.Random(1)
    rows = []
    for i in range(200):
        engineer = FeatureEngineer(5, 5000, 5)
        for pkt in benign_flow(rng, 0.0, i):
            engineer.process_packet(pkt)
        rows += [r["features"] for r in engineer.flush()]
    csv = tmp_path / "baseline.csv"
    pd.DataFrame(rows)[FEATURE_COLUMNS].to_csv(csv, index=False)

    artifacts = tmp_path / "does" / "not" / "exist"  # Regression: this used to raise FileNotFoundError
    manager = ModelManager(ModelConfig(artifact_dir=artifacts, baseline_path=csv))
    manager.load_or_train()
    assert any(artifacts.glob("*.joblib"))
