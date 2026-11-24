from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

EVENT_PATH = Path("artifacts/events.jsonl")


def load_events(path: Path) -> pd.DataFrame:
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    records = []
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # a half-written last line while the pipeline is running
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    df["time"] = pd.to_datetime(df["timestamp"], unit="s")
    return df


def render_overview(df: pd.DataFrame, window: int) -> None:
    latest = df.tail(window)
    col1, col2, col3 = st.columns(3)
    col1.metric("Flows scored", len(latest))
    col2.metric("Alerts", int((latest["label"] != "benign").sum()))
    col3.metric("Mean anomaly score", f"{latest['score'].mean():.4f}")

    st.subheader("Anomaly score")
    fig = px.scatter(
        latest,
        x="time",
        y="score",
        color="label",
        color_discrete_map={"benign": "#2a9d8f", "malicious": "#e63946"},
        title="IsolationForest score per flow (lower = more anomalous)",
    )
    st.plotly_chart(fig, width="stretch")

    st.subheader("Alerts")
    alerts = latest[latest["label"] != "benign"].copy()
    if alerts.empty:
        st.success("No alerts in this window.")
        return
    flow = pd.json_normalize(alerts["flow"].tolist()).set_index(alerts.index)
    alerts = alerts.join(flow[["src_ip", "dst_ip", "dst_port", "protocol"]])
    st.dataframe(
        alerts[["time", "label", "score", "src_ip", "dst_ip", "dst_port", "protocol"]].sort_values(
            "time", ascending=False
        ),
        width="stretch",
    )


def main() -> None:
    st.set_page_config(page_title="IDS Dashboard", layout="wide")
    st.title("Intrusion Detection System")
    st.caption(f"Reads {EVENT_PATH}. Start the detector with `python app.py --mock` or `--interface`.")

    auto = st.sidebar.checkbox("Auto-refresh every 3 s", value=True, key="auto")
    window = st.sidebar.slider("Flows to show", 100, 5000, 1000, step=100)

    df = load_events(EVENT_PATH)
    if df.empty:
        st.info("Waiting for events. Run `python app.py --mock` in another terminal.")
    else:
        render_overview(df, window)

    if auto:
        time.sleep(3)
        st.rerun()


if __name__ == "__main__":
    main()
