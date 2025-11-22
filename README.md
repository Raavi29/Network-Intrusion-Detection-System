# AI-Powered Intrusion Detection System (IDS)

This project implements a Python-first intrusion detection pipeline that captures live packets, engineers security-focused features, applies machine-learning models, and surfaces real-time alerts through a dashboard and outbound notifiers.

## High-Level Architecture

- **Packet Capture**: `scapy`/`pyshark` interfaces sniff raw packets or replay PCAP files for offline testing.
- **Feature Engineering**: Flow-aware aggregations extract metrics such as duration, packet rate, SYN counts, and payload sizes.
- **Anomaly Detection**: An `IsolationForest` pipeline (with pluggable models) classifies flows as benign, suspicious, or malicious.
- **Alerting & Storage**: Alerts stream to the console, optional webhooks, and JSONL artifacts for historical audits.
- **Dashboard**: A Streamlit interface visualizes traffic rates, alert feed, and model confidence in real time.

## Getting Started

### 1. Requirements

- Python 3.10+
- `pip` or `uv`
- Packet capture privileges (run as Administrator on Windows or with `sudo` on Linux/macOS)

### 2. Install Dependencies

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

### 3. Run the Detection Pipeline

```bash
python app.py --interface eth0
```

Flags:

- `--pcap path/to/file.pcap` – replay traffic instead of sniffing live
- `--mock` – generate synthetic packets (useful without elevated privileges)

### 4. Launch the Dashboard

```bash
streamlit run dashboard.py
```

The dashboard reads `artifacts/events.jsonl` and refreshes automatically.

## Project Structure

```
.
├── app.py                  # Orchestrates capture → features → model → alerts
├── dashboard.py            # Streamlit UI for real-time monitoring
├── requirements.txt        # Python dependencies
├── src/
│   ├── config.py           # Dataclasses for tunable settings
│   ├── packet_sniffer.py   # Scapy/pyshark and mock packet sources
│   ├── feature_engineer.py # Flow tracking and feature extraction
│   ├── model.py            # IsolationForest manager + persistence
│   ├── alerts.py           # Slack/email/console alert dispatching
│   ├── storage.py          # JSONL event logging utilities
│   └── pipeline.py         # Detection pipeline glue logic
├── data/
│   └── baseline.csv        # (Optional) Seed data for training
└── artifacts/
    ├── events.jsonl        # Rolling alert/event log
    └── model.joblib        # Persisted ML model
```

## Customization Ideas

- Swap in supervised models (RandomForest, XGBoost) with labeled traffic.
- Add signature-based rules for known attack fingerprints.
- Stream alerts to Slack, Discord, or email via environment variables.
- Deploy on Raspberry Pi for a low-cost home IDS appliance.

## Status & Next Steps

- [x] Python-based architecture scaffolding
- [ ] Implement packet capture and feature pipeline
- [ ] Train and persist anomaly model
- [ ] Build Streamlit dashboard and alert hooks

Contributions and issue reports are welcome!
