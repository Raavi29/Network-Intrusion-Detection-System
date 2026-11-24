# Network Intrusion Detection System

A Python IDS that groups packets into flows, scores each finished flow with an Isolation Forest, and raises an alert when a flow looks anomalous. It reads live traffic, replays PCAP files, or generates synthetic traffic, and shows the results in a Streamlit dashboard.

Status: a working prototype trained on a synthetic baseline. It has not been validated on real network data (see Limitations).

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
python -m pytest                          # 15 tests, about 25 seconds
python scripts/evaluate.py                # detection rates on synthetic attacks
```

`scripts/evaluate.py` runs 1,000 benign flows and 200 of each attack through the full pipeline (fixed seed 2026):

| Traffic | Result |
|---|---|
| Benign flows | 2 of 1,000 falsely flagged |
| SYN flood | 200 of 200 detected |
| Bulk exfiltration | 200 of 200 detected |
| UDP flood | 200 of 200 detected |
| Slow port scan | 0 of 200 detected |

## Limitations

- **Synthetic baseline.** With no `IDS_BASELINE_PATH`, the model trains on generated "normal" traffic. Real traffic looks different: when I captured ordinary TCP traffic on the loopback interface, every flow was flagged. Before trusting alerts, train on a CSV of your own benign flows (same 13 columns as `FEATURE_COLUMNS` in `src/model.py`) and set `IDS_BASELINE_PATH`.
- **The evaluation is a simulation.** The attacks come from `src/traffic.py`, written by the same author as the model's baseline. The numbers show the pipeline works. They do not predict accuracy on real attacks. A fair test needs a labelled dataset such as CIC-IDS2017 replayed with `--pcap`.
- **Port scans are missed by design.** Each probe is its own one-packet flow, and flows under 5 packets are not scored. Catching scans needs per-source features (distinct ports contacted per second), which this version does not have. `tests/test_model_detection.py` records this as a known blind spot.
- Not tested here: capture on Windows and macOS, and the Slack and email alerts against real services.

## Layout

```
app.py              command-line entry point
dashboard.py        Streamlit dashboard
src/                config, packets, packet_sniffer, feature_engineer, model, alerts, storage, pipeline, traffic
tests/              pytest suite
scripts/evaluate.py synthetic evaluation
archive/            an unrelated e-commerce site that was in this repository
```
