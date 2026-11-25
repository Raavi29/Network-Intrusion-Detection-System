"""Preview evaluation on CIC-IDS2017 from the labelled-flow CSVs only (no PCAPs).

    python scripts/evaluate_cic_csv.py --dir "TrafficLabelling " --out cic_preview.json

Trains on Monday (all benign) and tests on the other days. This checks the model and the 13 features on
real traffic. It does not test packet capture; for that use scripts/evaluate_pcap.py with the PCAPs.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.cicstats import evaluate_days, format_summary, read_day  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dir", required=True, help="folder with the CIC-IDS2017 *_ISCX.csv files")
    p.add_argument("--percentile", type=float, default=1.0, help="%% of benign training flows allowed to alert")
    p.add_argument("--out", help="write full results as JSON")
    a = p.parse_args()

    files = sorted(Path(a.dir).glob("*.csv"))
    monday = [f for f in files if f.name.startswith("Monday")]
    tests = [f for f in files if not f.name.startswith("Monday")]
    if len(monday) != 1 or not tests:
        raise SystemExit("expected one Monday file (training) and at least one other day (testing)")
    print("reading", monday[0].name, flush=True)
    train = read_day(monday[0])
    days = {}
    for f in tests:
        print("reading", f.name, flush=True)
        days[f.name.replace(".pcap_ISCX.csv", "")] = read_day(f)
    results = evaluate_days(train, days, train_percentile=a.percentile)
    print()
    print(format_summary(results))
    if a.out:
        Path(a.out).write_text(json.dumps(results, indent=2, default=float))
        print(f"\nfull results written to {a.out}")


if __name__ == "__main__":
    main()
