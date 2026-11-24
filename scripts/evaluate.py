"""Measure the detector on synthetic traffic, end to end (packets -> flows -> model).

    python scripts/evaluate.py

The traffic comes from src/traffic.py and the model is trained on a synthetic baseline, so the
numbers describe this simulation only. They say nothing about real networks. For that, replay a
labelled capture (for example CIC-IDS2017) with `python app.py --pcap`.
"""
from __future__ import annotations

import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import ModelConfig  # noqa: E402
from src.feature_engineer import FeatureEngineer  # noqa: E402
from src.model import ModelManager  # noqa: E402
from src.traffic import ATTACKS, benign_flow  # noqa: E402

SEED = 2026
N_BENIGN = 1000
N_PER_ATTACK = 200


def flagged_flows(model: ModelManager, packets) -> tuple[int, int]:
    """Return (flows scored, flows flagged malicious) for one group of packets."""
    engineer = FeatureEngineer(flow_timeout_s=5, max_flows=5000, min_packets=5)
    results = []
    for pkt in sorted(packets, key=lambda p: p.timestamp):
        results += engineer.process_packet(pkt)
    results += engineer.flush()
    flagged = sum(model.predict(r["features"], r["metadata"]).label == "malicious" for r in results)
    return len(results), flagged


def main() -> None:
    rng = random.Random(SEED)
    with tempfile.TemporaryDirectory() as tmp:
        model = ModelManager(ModelConfig(artifact_dir=Path(tmp)))
        model.load_or_train()

        scored = alarms = 0
        for i in range(N_BENIGN):
            s, f = flagged_flows(model, benign_flow(rng, 0.0, i))
            scored, alarms = scored + s, alarms + f
        print(f"benign traffic      : {alarms}/{scored} flows falsely flagged")

        caught_total = 0
        for name, make in ATTACKS.items():
            caught = sum(flagged_flows(model, make(rng, 0.0, i))[1] > 0 for i in range(N_PER_ATTACK))
            caught_total += caught
            print(f"{name:<20}: {caught}/{N_PER_ATTACK} attacks detected")
        total = N_PER_ATTACK * len(ATTACKS)
        print(f"overall             : {caught_total}/{total} attacks detected ({caught_total / total:.0%})")


if __name__ == "__main__":
    main()
