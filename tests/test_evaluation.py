import random

import pytest
from scapy.all import wrpcap

from src.evaluation import evaluate, extract_flows, flow_key, format_report, load_labels
from src.traffic import ATTACKS, benign_flow
from tests.test_pipeline import to_scapy

HEADER = " Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Label"


def csv_row(first_packet, label):
    p = first_packet
    proto = 6 if p.protocol == "TCP" else 17
    return f"{p.src_ip}-{p.dst_ip}-{p.src_port}-{p.dst_port}-{proto},{p.src_ip},{p.src_port},{p.dst_ip},{p.dst_port},{proto},x,{label}"


def write_day(tmp_path, name, n_benign, attacks, seed):
    """A synthetic capture plus a CIC-IDS2017-style label CSV (padded headers, numeric protocol)."""
    rng = random.Random(seed)
    packets, rows, flow_id = [], [], seed * 10_000
    for i in range(n_benign):
        flow = benign_flow(rng, i * 0.2, flow_id)
        packets += flow
        rows.append(csv_row(flow[0], "BENIGN"))
        flow_id += 1
    t = 1.0
    for attack, count in attacks.items():
        for _ in range(count):
            flow = ATTACKS[attack](rng, t, flow_id)
            packets += flow
            if attack == "port scan":  # one labelled flow per probe, as CICFlowMeter would
                rows += [csv_row(p, "PortScan") for p in flow]
            else:
                rows.append(csv_row(flow[0], attack))
            flow_id += 1
            t += 2.5
    pcap = tmp_path / f"{name}.pcap"
    wrpcap(str(pcap), [to_scapy(p) for p in sorted(packets, key=lambda p: p.timestamp)])
    csv = tmp_path / f"{name}.csv"
    csv.write_text(HEADER + "\n" + "\n".join(rows) + "\n", encoding="latin-1")
    return pcap, csv


def test_labels_match_in_both_directions_and_ignore_padded_headers(tmp_path):
    csv = tmp_path / "labels.csv"
    csv.write_text(HEADER + "\nid,10.0.0.1, 5000,10.0.0.2, 80,6,x,DoS Hulk\n", encoding="latin-1")
    labels = load_labels([csv])
    forward = ("10.0.0.1", "10.0.0.2", 5000, 80, "TCP")
    reverse = ("10.0.0.2", "10.0.0.1", 80, 5000, "TCP")
    assert labels.lookup(forward)[1] == "DoS Hulk"
    assert labels.lookup(reverse) == (forward, "DoS Hulk")
    assert labels.lookup(("10.0.0.1", "10.0.0.2", 5001, 80, "TCP")) is None


def test_a_reused_five_tuple_with_conflicting_labels_is_dropped(tmp_path):
    csv = tmp_path / "labels.csv"
    csv.write_text(
        HEADER + "\nid,10.0.0.1,5000,10.0.0.2,80,6,x,BENIGN\nid,10.0.0.1,5000,10.0.0.2,80,6,x,DoS Hulk\n",
        encoding="latin-1",
    )
    labels = load_labels([csv])
    assert labels.lookup(("10.0.0.1", "10.0.0.2", 5000, 80, "TCP")) is None
    assert labels.ambiguous == 1


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("day")
    train_pcap, _ = write_day(tmp, "monday", n_benign=250, attacks={}, seed=1)
    test_pcap, test_csv = write_day(
        tmp, "wednesday", n_benign=100, attacks={"SYN flood": 6, "bulk exfiltration": 2, "UDP flood": 2, "port scan": 4}, seed=2
    )
    train, _ = extract_flows(train_pcap, progress_every=0)
    test, _ = extract_flows(test_pcap, progress_every=0)
    return evaluate(train, test, load_labels([test_csv])), test


def test_every_scored_flow_is_matched_to_a_label(result):
    r, test = result
    assert r["test_flows_not_in_labels"] == 0
    assert r["test_flows_matched"] == len(test)


def test_volumetric_attacks_rank_above_benign_and_are_caught(result):
    r, _ = result
    assert r["auc_overall"] > 0.95
    for name in ("SYN flood", "bulk exfiltration", "UDP flood"):
        row = r["per_attack"][name]
        assert row["detected_calibrated"] == row["scored_flows"] > 0
    assert r["calibrated"]["false_positive_rate"] <= 0.05


def test_port_scan_blind_spot_is_reported_not_hidden(result):
    r, _ = result
    row = r["per_attack"].get("PortScan")
    assert row is not None and row["labelled_flows_in_csv"] == 4 * 30
    assert row["seen_by_ids"] == 0 and row["scored_flows"] == 0


def test_threshold_is_calibrated_on_training_data_only(result):
    r, _ = result
    # about 1% of benign training flows alert at the calibrated threshold, by construction
    assert -1.0 < r["calibrated"]["threshold"] < 0.5
    assert "benign training scores" in r["calibrated_note"]


def test_report_renders(result):
    r, _ = result
    text = format_report(r)
    assert "AUC" in text and "SYN flood" in text and "PortScan" in text
