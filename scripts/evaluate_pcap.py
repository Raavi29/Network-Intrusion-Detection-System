"""Evaluate the IDS on a labelled dataset (CIC-IDS2017).

    python scripts/evaluate_pcap.py \\
        --train-pcap Monday-WorkingHours.pcap \\
        --test-pcap  Wednesday-workingHours.pcap \\
        --labels     Wednesday-workingHours.pcap_ISCX.csv

Download the PCAPs and the "TrafficLabelling" CSVs from https://www.unb.ca/cic/datasets/ids-2017.html
Monday has no attacks, so it is the training set. Replaying a full day takes tens of minutes
(measure with --max-packets 1000000 first); use --max-packets for a quick trial.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation import evaluate, extract_flows, format_report, load_labels  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--train-pcap", required=True, help="benign-only capture (CIC-IDS2017 Monday)")
    p.add_argument("--test-pcap", required=True, help="labelled capture to test on")
    p.add_argument("--labels", required=True, nargs="+", help="labelled-flows CSV(s) for the test capture")
    p.add_argument("--max-packets", type=int, default=None, help="stop each PCAP after N packets (quick trial)")
    p.add_argument("--percentile", type=float, default=1.0, help="calibrate the threshold so this %% of benign training flows alert")
    p.add_argument("--out", help="write the full results as JSON to this path")
    a = p.parse_args()

    print("Reading benign training traffic ...", flush=True)
    train, n_train = extract_flows(a.train_pcap, max_packets=a.max_packets)
    print(f"  {n_train:,} packets -> {len(train):,} flows", flush=True)
    print("Reading test traffic ...", flush=True)
    test, n_test = extract_flows(a.test_pcap, max_packets=a.max_packets)
    print(f"  {n_test:,} packets -> {len(test):,} flows", flush=True)
    print("Reading labels ...", flush=True)
    labels = load_labels(a.labels)
    print(f"  {len(labels.label):,} labelled flows\n", flush=True)

    results = evaluate(train, test, labels, train_percentile=a.percentile)
    print(format_report(results))
    if a.out:
        Path(a.out).write_text(json.dumps(results, indent=2))
        print(f"\nfull results written to {a.out}")


if __name__ == "__main__":
    main()
