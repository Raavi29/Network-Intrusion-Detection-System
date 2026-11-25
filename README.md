# Network Intrusion Detection System

A Python IDS that groups packets into flows, scores each finished flow with an Isolation Forest, and raises an alert when a flow looks anomalous. It reads live traffic, replays PCAP files, or generates synthetic traffic, and shows the results in a Streamlit dashboard.

Status: a working pipeline with a weak detector. On real traffic (CIC-IDS2017) the Isolation Forest performs poorly; see the results and limitations below.

## How it works

```
packet source -> FeatureEngineer -> ModelManager -> EventStore (+ alerts) -> dashboard
 (scapy / PCAP     (flows, 13        (IsolationForest   artifacts/events.jsonl
  / mock)           features)         + StandardScaler)
```

- A flow is one direction of a 5-tuple (source and destination address and port, protocol).
- A flow is scored when it sends a FIN or has been quiet for 5 seconds (`IDS_FLOW_TIMEOUT_S`). Flows shorter than 5 packets (`IDS_MIN_PACKETS`) are not scored.
- The 13 features are packet and byte counts, duration, packet and bit rate, packet length mean and spread, SYN, FIN and ACK ratios, mean inter-arrival time, and TCP/UDP flags.
- A flow whose Isolation Forest score is below `IDS_ANOMALY_THRESHOLD` (default -0.05) is labelled `malicious`.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Live capture needs root (Linux/macOS) or Administrator (Windows). Using a BPF filter (`--bpf`) also needs libpcap (Npcap on Windows).

## Run

```bash
python app.py --mock                      # synthetic traffic, no privileges needed
python app.py --pcap capture.pcap         # replay a file, then exit
sudo python app.py --interface eth0       # live capture
streamlit run dashboard.py                # dashboard, reads artifacts/events.jsonl
```

Optional alerts go to Slack or email when the `IDS_SLACK_WEBHOOK` or `IDS_SMTP_*` variables are set (see `src/config.py`).

## Tests and evaluation

```bash
python -m pytest                          # 27 tests, about 50 seconds
python scripts/evaluate.py                # detection rates on synthetic attacks (a simulation)
```

`scripts/evaluate.py` runs 1,000 benign flows and 200 of each attack through the full pipeline (fixed seed 2026):

| Traffic | Result |
|---|---|
| Benign flows | 2 of 1,000 falsely flagged |
| SYN flood | 200 of 200 detected |
| Bulk exfiltration | 200 of 200 detected |
| UDP flood | 200 of 200 detected |
| Slow port scan | 0 of 200 detected |

## Evaluating on real data (CIC-IDS2017)

`scripts/evaluate_pcap.py` trains on a benign capture and tests on a labelled one. Download the PCAPs and the "TrafficLabelling" CSVs from the [CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html), then:

```bash
python scripts/evaluate_pcap.py \
    --train-pcap Monday-WorkingHours.pcap \
    --test-pcap  Wednesday-workingHours.pcap \
    --labels     Wednesday-workingHours.pcap_ISCX.csv \
    --out wednesday.json
```

- Monday has no attacks, so the model learns "normal" from real traffic. Try `--max-packets 1000000` first to time it.
- The alert threshold is set from the benign training data only (`--percentile`, default 1% of training flows alert), never from the test labels.
- Flows are matched to the dataset's labels by 5-tuple, in either direction. Flows missing from the CSV are counted and left out.
- The report gives AUC (threshold-free), precision, recall and false-positive rate at the default and the calibrated threshold, and one row per attack type. Attack types the detector never scored, such as port scans, still appear, with `seen` = 0.
- The test is in `tests/test_evaluation.py`, which runs the same code on a synthetic day in the same CSV format. Those results say nothing about real data.

## Result on real data: CIC-IDS2017 flow statistics

`scripts/evaluate_cic_csv.py` trains on Monday (all benign) and tests on the other four days, using the labelled-flow CSVs from the dataset (no PCAPs). It rebuilds the 13 features from CICFlowMeter's statistics, so it tests the model and the feature design on real traffic, **not** the packet capture. Flows with fewer than 5 forward packets are never scored.

| Measure | Result |
|---|---|
| Flows tested / attacks among them | 2.30 million / 557,646 |
| Flows long enough to score | 596,374 |
| AUC, attack vs benign (0.5 = coin flip) | 0.78 |
| False alarms on benign test flows (threshold set for 1% on Monday) | 3.6% |
| DoS Hulk (144,430 flows scored) | 0 detected |
| DDoS (46,619 scored) | 0 detected, AUC 0.42 |
| PortScan (158,930 flows) | 131 scored, 0 detected |

**The unsupervised Isolation Forest does not work on real traffic.** Training it on the same day's benign flows removes the Monday-to-later-day shift but does not rescue it (AUC 0.30 to 0.84 depending on the day). The 13 features do carry signal: a supervised random forest reaches AUC 0.98 to 1.0 within a day, and 0.83 on DDoS and 0.98 on PortScan when trained on Monday to Wednesday, but it fails on Bot and Infiltration. The synthetic numbers above show the pipeline runs. They do not show the detector is good.

## Limitations

- **Synthetic baseline.** With no `IDS_BASELINE_PATH`, the model trains on generated "normal" traffic. Real traffic looks different: when I captured ordinary TCP traffic on the loopback interface, every flow was flagged. Before trusting alerts, train on a CSV of your own benign flows (same 13 columns as `FEATURE_COLUMNS` in `src/model.py`) and set `IDS_BASELINE_PATH`.
- **The synthetic evaluation is a simulation.** The attacks come from `src/traffic.py`, written by the same author as the model's baseline. The numbers show the pipeline works. They do not predict accuracy on real attacks. A fair test needs real labelled traffic: see "Evaluating on real data" above.
- **Port scans are missed by design.** Each probe is its own one-packet flow, and flows under 5 packets are not scored. Catching scans needs per-source features (distinct ports contacted per second), which this version does not have. `tests/test_model_detection.py` records this as a known blind spot.
- Not tested here: capture on Windows and macOS, and the Slack and email alerts against real services.

## Layout

```
app.py              command-line entry point
dashboard.py        Streamlit dashboard
src/                config, packets, packet_sniffer, feature_engineer, model, alerts, storage, pipeline, traffic, evaluation, pcapfast
tests/              pytest suite
scripts/            evaluate.py (synthetic), evaluate_pcap.py (labelled dataset)
archive/            an unrelated e-commerce site that was in this repository
```
