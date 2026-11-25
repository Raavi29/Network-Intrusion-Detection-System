"""Preview evaluation from CIC-IDS2017 flow statistics (no PCAPs needed).

CICFlowMeter already turned each flow into statistics and labelled it. This module rebuilds our 13
features for the forward (initiator) direction from those statistics, so the Isolation Forest can be
trained and tested on real traffic with real labels.

What this does and does not test:
  * It tests the model and the 13-feature design on real traffic.
  * It does NOT test our packet capture or flow assembly. The features are approximations of what
    FeatureEngineer computes from packets (see the notes in `features_from_cic`).
Use `evaluate_pcap.py` with the PCAPs for the real end-to-end result.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

import numpy as np
import pandas as pd

from .config import ModelConfig
from .evaluation import auc, is_benign, threshold_metrics
from .model import FEATURE_COLUMNS, ModelManager

NEEDED = [
    "Protocol", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Fwd Header Length", "Fwd Packet Length Std", "Fwd IAT Total", "Fwd IAT Mean",
    "SYN Flag Count", "FIN Flag Count", "ACK Flag Count", "Label",
]
MIN_PACKETS = 5  # same cut-off as the live pipeline: shorter flows are never scored
ETHERNET_HEADER = 14


def clean_label(label: str) -> str:
    return label.strip().replace("\x96", "-").replace("�", "-")


def read_day(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="latin-1", usecols=lambda c: c.strip() in NEEDED, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df = df.dropna(subset=NEEDED)
    df["Label"] = df["Label"].astype(str).map(clean_label)
    return df.reset_index(drop=True)


def features_from_cic(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Return (13 features, labels, scorable mask) for the forward direction of each flow.

    Approximations: lengths are payload-only in the CSV, so header bytes are added back
    (Fwd Header Length plus 14 Ethernet bytes per packet); the SYN/FIN/ACK ratios use whole-flow
    flag counts over whole-flow packets because the CSV does not split flags by direction.
    """
    pkts = df["Total Fwd Packets"].clip(lower=1).astype(float)
    total_pkts = (df["Total Fwd Packets"] + df["Total Backward Packets"]).clip(lower=1).astype(float)
    byte_count = df["Total Length of Fwd Packets"] + df["Fwd Header Length"] + ETHERNET_HEADER * pkts
    duration = (df["Fwd IAT Total"] / 1e6).clip(lower=1e-3)
    feats = pd.DataFrame(
        {
            "packet_count": pkts,
            "byte_count": byte_count,
            "duration": duration,
            "pps": pkts / duration,
            "bps": byte_count * 8 / duration,
            "avg_packet_len": byte_count / pkts,
            "std_packet_len": df["Fwd Packet Length Std"].fillna(0),
            "syn_ratio": df["SYN Flag Count"] / total_pkts,
            "fin_ratio": df["FIN Flag Count"] / total_pkts,
            "ack_ratio": df["ACK Flag Count"] / total_pkts,
            "avg_inter_arrival": df["Fwd IAT Mean"].clip(lower=0) / 1e6,
            "protocol_tcp": (df["Protocol"] == 6).astype(float),
            "protocol_udp": (df["Protocol"] == 17).astype(float),
        }
    )[FEATURE_COLUMNS]
    return feats, df["Label"], df["Total Fwd Packets"] >= MIN_PACKETS


def evaluate_days(
    train: pd.DataFrame,
    days: Dict[str, pd.DataFrame],
    default_threshold: float = -0.05,
    train_percentile: float = 1.0,
    artifact_dir: Optional[Path] = None,
    seed: int = 42,
) -> Dict[str, object]:
    """Train on a benign day, test on labelled days. Returns overall and per-day results."""
    import tempfile

    x_train, y_train, ok_train = features_from_cic(train)
    benign_train = x_train[ok_train & y_train.map(is_benign)]
    if len(benign_train) < 100:
        raise ValueError("need at least 100 benign training flows with 5+ forward packets")
    with tempfile.TemporaryDirectory() as tmp:
        folder = artifact_dir or Path(tmp)
        folder.mkdir(parents=True, exist_ok=True)
        baseline = folder / "baseline.csv"
        benign_train.to_csv(baseline, index=False)
        model = ModelManager(ModelConfig(artifact_dir=folder, baseline_path=baseline))
        model.load_or_train()
        scores_train = model.pipeline.decision_function(benign_train)
        calibrated = float(np.percentile(scores_train, train_percentile))

        per_day, pooled = {}, []
        for day, df in days.items():
            x, labels, ok = features_from_cic(df)
            decision = pd.Series(model.pipeline.decision_function(x[ok]), index=x[ok].index)
            attack = ~labels.map(is_benign)
            per_day[day] = _summarise(labels, attack, ok, decision, default_threshold, calibrated)
            pooled.append(pd.DataFrame({"label": labels, "attack": attack, "ok": ok, "decision": decision}))
        allrows = pd.concat(pooled, ignore_index=True)
        y_all = allrows["attack"]
        overall = _summarise(allrows["label"], y_all, allrows["ok"], allrows["decision"], default_threshold, calibrated)
        return {
            "train_flows_total": int(len(train)),
            "train_flows_used": int(len(benign_train)),
            "calibrated_threshold": calibrated,
            "overall": overall,
            "per_day": per_day,
        }


def _summarise(labels, attack, ok, decision, default_threshold, calibrated) -> Dict[str, object]:
    scored = ok & decision.notna()
    d = decision[scored].to_numpy()
    y = attack[scored].astype(int).to_numpy()
    names = labels[scored].to_numpy()
    out: Dict[str, object] = {
        "flows": int(len(labels)),
        "benign_flows": int((~attack).sum()),
        "attack_flows": int(attack.sum()),
        "scored_flows": int(scored.sum()),
        "auc": auc(y, -d) if len(y) else None,
        "configured": threshold_metrics(y, d, default_threshold) if len(y) else None,
        "calibrated": threshold_metrics(y, d, calibrated) if len(y) else None,
    }
    per_attack = {}
    benign_d = d[y == 0]
    for lab in sorted(set(labels[attack])):
        total = int((labels == lab).sum())
        m = names == lab
        row = {"flows_in_csv": total, "scored": int(m.sum()), "detected": int((d[m] < calibrated).sum())}
        row["auc_vs_benign"] = (
            auc(np.r_[np.zeros(len(benign_d)), np.ones(int(m.sum()))], -np.r_[benign_d, d[m]]) if m.any() and len(benign_d) else None
        )
        per_attack[lab] = row
    out["per_attack"] = per_attack
    return out


def format_summary(r: Dict[str, object]) -> str:
    def pct(x):
        return "n/a" if x is None else f"{x:.1%}"

    def num(x):
        return "n/a" if x is None else f"{x:.3f}"

    lines = [
        f"trained on {r['train_flows_used']:,} benign Monday flows (of {r['train_flows_total']:,}; flows under {MIN_PACKETS} forward packets are never scored)",
        f"alert threshold {r['calibrated_threshold']:+.4f}, set so ~1% of benign training flows alert",
        "",
    ]
    o = r["overall"]
    c = o["calibrated"]
    lines += [
        f"ALL TEST DAYS: {o['flows']:,} flows ({o['attack_flows']:,} attacks), {o['scored_flows']:,} scored",
        f"  AUC {num(o['auc'])}   precision {pct(c['precision'])}   recall {pct(c['recall'])}   false-positive rate {pct(c['false_positive_rate'])}",
        f"  (attack recall counts only scored flows; attacks too short to score are listed below)",
        "",
        f"{'day / attack type':<44}{'flows':>9}{'scored':>9}{'detected':>10}{'scored%':>9}{'recall*':>9}{'AUC':>7}",
    ]
    for day, d in r["per_day"].items():
        lines.append(f"{day}  (benign flows: {d['benign_flows']:,}, scored {d['scored_flows']:,} total)")
        for lab, row in d["per_attack"].items():
            sc = row["scored"] / row["flows_in_csv"] if row["flows_in_csv"] else 0
            rec = row["detected"] / row["scored"] if row["scored"] else None
            lines.append(
                f"  {lab:<42}{row['flows_in_csv']:>9,}{row['scored']:>9,}{row['detected']:>10,}{sc:>9.0%}{pct(rec):>9}{num(row['auc_vs_benign']):>7}"
            )
    lines += [
        "",
        "scored%  : share of that attack's flows long enough (5+ forward packets) to be scored at all",
        "recall*  : detected / scored.  Multiply by scored% to get recall over every flow of that attack.",
    ]
    return "\n".join(lines)
