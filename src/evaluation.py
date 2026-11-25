"""Evaluate the detector on a labelled dataset such as CIC-IDS2017.

Protocol (the usual one for anomaly detectors):
  1. Train only on benign traffic (CIC-IDS2017 Monday is attack-free).
  2. Pick the alert threshold from that benign training data alone, never from the test labels.
  3. Replay a labelled capture, give each scored flow the label of the same 5-tuple in the
     dataset's labelled-flows CSV, and measure.

The dataset's labels come from CICFlowMeter flows, which are bidirectional and use a 120 s
timeout. Ours are one-way flows with a 5 s timeout, so labels are matched on the 5-tuple in
either direction. Flows that are not in the CSV are left out and counted.
"""
from __future__ import annotations

import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

from .config import ModelConfig
from .feature_engineer import FeatureEngineer, FlowResult
from .model import FEATURE_COLUMNS, ModelManager
from .packet_sniffer import PcapReader, packet_to_observation
from .pcapfast import is_supported_pcap, read_pcap

Key = Tuple[str, str, int, int, str]

PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP"}
COLUMN_ALIASES = {
    "Src IP": "Source IP",
    "Src Port": "Source Port",
    "Dst IP": "Destination IP",
    "Dst Port": "Destination Port",
}
WANTED = {"Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Label"}


def is_benign(label: str) -> bool:
    return label.strip().upper() == "BENIGN"


# ---------------------------------------------------------------- packets -> flows

def extract_flows(
    pcap_path: str | Path,
    max_packets: Optional[int] = None,
    flow_timeout_s: float = 5.0,
    min_packets: int = 5,
    max_flows: int = 200_000,
    progress_every: int = 1_000_000,
) -> Tuple[List[FlowResult], int]:
    """Replay a PCAP through the FeatureEngineer. Returns (scored flows, packets read)."""
    engineer = FeatureEngineer(flow_timeout_s=flow_timeout_s, max_flows=max_flows, min_packets=min_packets)
    flows: List[FlowResult] = []
    count = 0
    for obs in _observations(pcap_path):
        count += 1
        if obs is not None:
            flows += engineer.process_packet(obs)
        if max_packets and count >= max_packets:
            break
        if progress_every and count % progress_every == 0:
            print(f"  {count:,} packets, {len(flows):,} flows scored so far", flush=True)
    flows += engineer.flush()
    return flows, count


def _observations(pcap_path: str | Path):
    """Fast reader for classic Ethernet PCAPs (CIC-IDS2017); scapy for anything else (pcapng, IPv6-only links)."""
    if is_supported_pcap(pcap_path):
        yield from read_pcap(pcap_path)
        return
    if PcapReader is None:
        raise RuntimeError("scapy is not installed")
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            yield packet_to_observation(pkt)


# ---------------------------------------------------------------- labels

@dataclass
class LabelMap:
    canon: Dict[Key, Key] = field(default_factory=dict)  # any direction -> canonical (forward) key
    label: Dict[Key, str] = field(default_factory=dict)  # canonical key -> label
    ambiguous: int = 0

    def lookup(self, key: Key) -> Optional[Tuple[Key, str]]:
        canonical = self.canon.get(key)
        if canonical is None or canonical not in self.label:
            return None
        return canonical, self.label[canonical]

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = defaultdict(int)
        for lab in self.label.values():
            out[lab] += 1
        return dict(out)


def load_labels(csv_paths: Iterable[str | Path]) -> LabelMap:
    """Read one or more CIC-IDS2017 'TrafficLabelling' CSVs into a LabelMap."""
    result = LabelMap()
    conflicted: set = set()
    for path in csv_paths:
        df = pd.read_csv(
            path,
            encoding="latin-1",
            usecols=lambda c: COLUMN_ALIASES.get(c.strip(), c.strip()) in WANTED,
            low_memory=False,
        )
        df.columns = [COLUMN_ALIASES.get(c.strip(), c.strip()) for c in df.columns]
        df = df.dropna(subset=list(WANTED))
        rows = zip(
            df["Source IP"].astype(str).str.strip(),
            df["Destination IP"].astype(str).str.strip(),
            df["Source Port"].astype(int),
            df["Destination Port"].astype(int),
            df["Protocol"].astype(int),
            df["Label"].astype(str).str.strip(),
        )
        for src, dst, sport, dport, proto, lab in rows:
            name = PROTOCOLS.get(proto, "OTHER")
            fwd: Key = (src, dst, sport, dport, name)
            rev: Key = (dst, src, dport, sport, name)
            old = result.label.get(fwd)
            if old is not None and old != lab:
                conflicted.add(fwd)  # same 5-tuple reused with a different label
            result.label[fwd] = lab
            result.canon[fwd] = fwd
            result.canon.setdefault(rev, fwd)
    for key in conflicted:
        result.label.pop(key, None)
    result.ambiguous = len(conflicted)
    return result


# ---------------------------------------------------------------- scoring and metrics

def flow_key(result: FlowResult) -> Key:
    m = result["metadata"]
    return (str(m["src_ip"]), str(m["dst_ip"]), int(m["src_port"]), int(m["dst_port"]), str(m["protocol"]))


def feature_frame(flows: List[FlowResult]) -> pd.DataFrame:
    return pd.DataFrame([f["features"] for f in flows], columns=FEATURE_COLUMNS)


def train_model(train_flows: List[FlowResult], artifact_dir: Path) -> ModelManager:
    if len(train_flows) < 100:
        raise ValueError(f"only {len(train_flows)} benign training flows; need at least 100")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    baseline = artifact_dir / "baseline.csv"
    feature_frame(train_flows).to_csv(baseline, index=False)
    manager = ModelManager(ModelConfig(artifact_dir=artifact_dir, baseline_path=baseline))
    manager.load_or_train()
    return manager


def auc(y_true: np.ndarray, anomaly: np.ndarray) -> Optional[float]:
    """Probability that a random attack flow scores as more anomalous than a random benign flow."""
    from sklearn.metrics import roc_auc_score

    if y_true.min() == y_true.max():
        return None
    return float(roc_auc_score(y_true, anomaly))


def threshold_metrics(y_true: np.ndarray, decision: np.ndarray, threshold: float) -> Dict[str, Optional[float]]:
    pred = decision < threshold
    tp = int((pred & (y_true == 1)).sum())
    fp = int((pred & (y_true == 0)).sum())
    fn = int((~pred & (y_true == 1)).sum())
    tn = int((~pred & (y_true == 0)).sum())
    return {
        "threshold": float(threshold),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def evaluate(
    train_flows: List[FlowResult],
    test_flows: List[FlowResult],
    labels: LabelMap,
    default_threshold: float = -0.05,
    train_percentile: float = 1.0,
    artifact_dir: Optional[Path] = None,
) -> Dict[str, object]:
    """Train on benign flows, then score and measure the labelled test flows."""
    with tempfile.TemporaryDirectory() as tmp:
        model = train_model(train_flows, artifact_dir or Path(tmp))
        pipeline = model.pipeline
        train_scores = pipeline.decision_function(feature_frame(train_flows))
        # Calibrated on benign training traffic only: about `train_percentile`% of it would alert.
        calibrated = float(np.percentile(train_scores, train_percentile))

        matched_idx, names, tags, seen_keys = [], [], [], defaultdict(set)
        unmatched = 0
        for i, flow in enumerate(test_flows):
            hit = labels.lookup(flow_key(flow))
            if hit is None:
                unmatched += 1
                continue
            canonical, lab = hit
            matched_idx.append(i)
            names.append(lab)
            tags.append(0 if is_benign(lab) else 1)
            seen_keys[lab].add(canonical)

        if not matched_idx:
            raise ValueError("no test flow matched a labelled flow; check that the PCAP and CSV are from the same day")
        decision = pipeline.decision_function(feature_frame([test_flows[i] for i in matched_idx]))
        y = np.array(tags)
        names_arr = np.array(names)
        benign_mask = y == 0

        per_attack = {}
        label_totals = labels.counts()
        # Every attack type in the CSV gets a row, including ones the IDS never scored (short flows).
        for lab in sorted(l for l in label_totals if not is_benign(l)):
            m = names_arr == lab
            row = {
                "labelled_flows_in_csv": label_totals.get(lab, 0),
                "seen_by_ids": len(seen_keys[lab]),  # distinct labelled flows that produced a scored flow
                "scored_flows": int(m.sum()),
            }
            sel = m | benign_mask
            row["auc_vs_benign"] = auc(y[sel], -decision[sel]) if m.any() else None
            for tname, thr in (("configured", default_threshold), ("calibrated", calibrated)):
                row[f"detected_{tname}"] = int((decision[m] < thr).sum())
            per_attack[lab] = row

        benign_csv = sum(n for lab, n in label_totals.items() if is_benign(lab))
        return {
            "train_flows": len(train_flows),
            "test_flows_scored": len(test_flows),
            "test_flows_matched": len(matched_idx),
            "test_flows_not_in_labels": unmatched,
            "ambiguous_label_keys_dropped": labels.ambiguous,
            "benign_flows_in_csv": benign_csv,
            "benign_flows_matched": int(benign_mask.sum()),
            "attack_flows_matched": int((y == 1).sum()),
            "auc_overall": auc(y, -decision),
            "configured": threshold_metrics(y, decision, default_threshold),
            "calibrated": threshold_metrics(y, decision, calibrated),
            "calibrated_note": f"threshold = {train_percentile}th percentile of benign training scores",
            "per_attack": per_attack,
        }


def format_report(r: Dict[str, object]) -> str:
    def pct(x):
        return "n/a" if x is None else f"{x:.1%}"

    def num(x):
        return "n/a" if x is None else f"{x:.3f}"

    lines = [
        f"benign training flows      : {r['train_flows']:,}",
        f"test flows scored          : {r['test_flows_scored']:,} "
        f"({r['test_flows_matched']:,} matched to labels, {r['test_flows_not_in_labels']:,} not in the CSV)",
        f"matched benign / attack    : {r['benign_flows_matched']:,} / {r['attack_flows_matched']:,}",
        f"AUC (attack vs benign)     : {num(r['auc_overall'])}   (0.5 = coin flip, 1.0 = perfect)",
        "",
    ]
    for name in ("configured", "calibrated"):
        m = r[name]
        extra = f"  [{r['calibrated_note']}]" if name == "calibrated" else ""
        lines += [
            f"threshold {name:<10} ({m['threshold']:+.4f}){extra}",
            f"  precision {pct(m['precision'])}  recall {pct(m['recall'])}  false-positive rate {pct(m['false_positive_rate'])}",
            f"  TP {m['tp']:,}  FP {m['fp']:,}  FN {m['fn']:,}  TN {m['tn']:,}",
        ]
    lines += ["", f"{'attack type':<28}{'in CSV':>9}{'seen':>9}{'scored':>9}{'caught*':>9}{'caught**':>10}{'AUC':>7}"]
    for lab, row in r["per_attack"].items():
        lines.append(
            f"{lab:<28}{row['labelled_flows_in_csv']:>9,}{row['seen_by_ids']:>9,}{row['scored_flows']:>9,}"
            f"{row['detected_configured']:>9,}{row['detected_calibrated']:>10,}{num(row['auc_vs_benign']):>7}"
        )
    lines += [
        "",
        "in CSV  : labelled flows of that type in the dataset's CSV",
        "seen    : of those, how many produced at least one scored flow (short flows are never scored)",
        "scored  : scored one-way flows carrying that label",
        "caught* : scored flows alerted at the configured threshold; caught** : at the calibrated threshold",
    ]
    return "\n".join(lines)
