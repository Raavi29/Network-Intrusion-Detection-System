from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

EVENT_PATH = Path("artifacts/events.jsonl")
REFRESH_INTERVAL = 3


@st.cache_data(ttl=REFRESH_INTERVAL)
def load_events(path: Path) -> pd.DataFrame:
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    records = []
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not records:
        return pd.DataFrame()
    return pd.DataFrame(records)


def main() -> None:
    st.set_page_config(page_title="AI IDS Dashboard", layout="wide")
    st.title("AI-Powered Intrusion Detection System")
    st.caption("Live traffic overview, anomaly scores, and alert feed")

    placeholder = st.empty()
    while True:
        df = load_events(EVENT_PATH)
        with placeholder.container():
            if df.empty:
                st.info("Waiting for events... run `python app.py --mock` to generate traffic.")
            else:
                render_overview(df)
        time.sleep(REFRESH_INTERVAL)


def render_overview(df: pd.DataFrame) -> None:
    latest = df.tail(1000)
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Flows", len(latest))
    col2.metric("Alerts", int((latest["label"] != "benign").sum()))
    col3.metric("Avg Anomaly Score", f"{latest['score'].mean():.4f}")

    st.subheader("Anomaly Score Trend")
    fig = px.line(latest, y="score", title="IsolationForest score (lower = more anomalous)")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Alerts")
    alert_df = latest[latest["label"] != "benign"]
    if alert_df.empty:
        st.success("No alerts triggered in this window.")
    else:
        st.dataframe(alert_df[["timestamp", "label", "score", "flow"]].sort_values("timestamp", ascending=False))


if __name__ == "__main__":
    main()

