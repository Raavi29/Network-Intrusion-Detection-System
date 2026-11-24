import random

from src.feature_engineer import FeatureEngineer
from src.packets import PacketObservation
from src.traffic import benign_flow


def run(engineer, packets):
    results = []
    for pkt in sorted(packets, key=lambda p: p.timestamp):
        results += engineer.process_packet(pkt)
    return results + engineer.flush()


def pkt(t, src="192.168.1.5", sport=40000, fin=False):
    return PacketObservation(t, src, "10.0.0.5", sport, 443, "TCP", 500, fin_flag=fin, ack_flag=True)


def test_completed_flow_is_scored_once_with_all_its_packets():
    # Regression: the old code scored the first 5 packets of a flow again and again.
    flow = benign_flow(random.Random(1), 0.0, 1)
    results = run(FeatureEngineer(5, 5000, 5), flow)
    assert len(results) == 1
    assert results[0]["features"]["packet_count"] == len(flow)


def test_flows_below_the_minimum_are_not_scored():
    assert run(FeatureEngineer(5, 5000, 5), [pkt(0.0), pkt(0.1)]) == []


def test_fin_finishes_a_flow_immediately():
    engineer = FeatureEngineer(5, 5000, 5)
    packets = [pkt(i * 0.1) for i in range(5)] + [pkt(0.5, fin=True)]
    emitted = []
    for p in packets:
        emitted += engineer.process_packet(p)
    assert len(emitted) == 1
    assert emitted[0]["features"]["packet_count"] == 6
    assert engineer.flows == {}


def test_interleaved_flows_stay_separate():
    a = [pkt(i * 0.1, sport=1111) for i in range(7)]
    b = [pkt(i * 0.1 + 0.05, sport=2222) for i in range(9)]
    results = run(FeatureEngineer(5, 5000, 5), a + b)
    assert sorted(r["features"]["packet_count"] for r in results) == [7, 9]


def test_idle_flow_expires_when_later_traffic_arrives():
    engineer = FeatureEngineer(flow_timeout_s=5, max_flows=5000, min_packets=5)
    emitted = []
    for i in range(6):
        emitted += engineer.process_packet(pkt(i * 0.1))
    assert emitted == []  # still open
    emitted += engineer.process_packet(pkt(100.0, sport=5555))  # an unrelated packet, much later
    assert len(emitted) == 1
    assert emitted[0]["features"]["packet_count"] == 6


def test_oldest_flows_are_scored_not_dropped_when_the_table_is_full():
    engineer = FeatureEngineer(flow_timeout_s=5, max_flows=10, min_packets=2)
    emitted = []
    for flow_no in range(12):
        for k in range(3):
            emitted += engineer.process_packet(pkt(flow_no + k * 0.01, sport=3000 + flow_no))
    assert len(engineer.flows) <= 10
    assert emitted, "evicted flows must still be scored"
