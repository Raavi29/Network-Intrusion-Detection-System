import numpy as np
import pandas as pd

from src.cicstats import NEEDED, evaluate_days, features_from_cic, format_summary


def frame(rows):
    base = dict.fromkeys(NEEDED, 0)
    return pd.DataFrame([{**base, **r} for r in rows])


def test_features_are_rebuilt_from_cicflowmeter_columns():
    df = frame([
        {"Protocol": 6, "Total Fwd Packets": 10, "Total Backward Packets": 10, "Total Length of Fwd Packets": 1000,
         "Fwd Header Length": 200, "Fwd Packet Length Std": 50, "Fwd IAT Total": 2_000_000, "Fwd IAT Mean": 200_000,
         "SYN Flag Count": 2, "FIN Flag Count": 2, "ACK Flag Count": 10, "Label": "BENIGN"},
        {"Protocol": 6, "Total Fwd Packets": 3, "Label": "PortScan"},
    ])
    x, labels, scorable = features_from_cic(df)
    row = x.iloc[0]
    assert row["packet_count"] == 10
    assert row["byte_count"] == 1000 + 200 + 14 * 10  # payload + headers + Ethernet
    assert row["duration"] == 2.0 and row["pps"] == 5.0
    assert row["syn_ratio"] == 0.1 and row["avg_inter_arrival"] == 0.2 and row["protocol_tcp"] == 1
    assert list(scorable) == [True, False]  # flows under 5 forward packets are never scored


def synthetic_day(rng, n, attack=None, n_attack=0):
    rows = []
    for _ in range(n):
        pk = int(rng.integers(8, 40)); dur = rng.uniform(1, 6)
        rows.append({"Protocol": 6, "Total Fwd Packets": pk, "Total Backward Packets": pk, "Total Length of Fwd Packets": pk * 400,
                     "Fwd Header Length": pk * 40, "Fwd Packet Length Std": 100, "Fwd IAT Total": dur * 1e6,
                     "Fwd IAT Mean": dur * 1e6 / pk, "SYN Flag Count": 1, "FIN Flag Count": 1, "ACK Flag Count": pk, "Label": "BENIGN"})
    for _ in range(n_attack):
        rows.append({"Protocol": 6, "Total Fwd Packets": 5000, "Total Backward Packets": 0, "Total Length of Fwd Packets": 0,
                     "Fwd Header Length": 5000 * 20, "Fwd Packet Length Std": 0, "Fwd IAT Total": 1e6,
                     "Fwd IAT Mean": 200, "SYN Flag Count": 5000, "FIN Flag Count": 0, "ACK Flag Count": 0, "Label": attack})
    rows += [{"Protocol": 6, "Total Fwd Packets": 1, "Label": "PortScan"}] * 30  # too short to score
    return frame(rows)


def test_evaluation_catches_a_flood_and_reports_the_unscorable_attack():
    rng = np.random.default_rng(0)
    result = evaluate_days(synthetic_day(rng, 1000), {"day": synthetic_day(rng, 500, "SYN flood", 20)})
    attacks = result["per_day"]["day"]["per_attack"]
    assert attacks["SYN flood"]["detected"] == attacks["SYN flood"]["scored"] == 20
    assert attacks["PortScan"]["flows_in_csv"] == 30 and attacks["PortScan"]["scored"] == 0
    assert result["overall"]["auc"] > 0.95
    assert "PortScan" in format_summary(result)
