import json
import random

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

from src.config import AppConfig, ModelConfig, SnifferConfig
from src.packets import PacketObservation
from src.pipeline import DetectionPipeline
from src.traffic import ATTACKER_IP, ATTACKS, benign_flow


def make_pipeline(tmp_path, **sniffer):
    config = AppConfig(model=ModelConfig(artifact_dir=tmp_path), sniffer=SnifferConfig(**sniffer))
    pipeline = DetectionPipeline(config)
    pipeline.model_manager.load_or_train()
    return pipeline


def read_events(tmp_path):
    return [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]


def traffic(seed=5):
    rng = random.Random(seed)
    packets = [p for i in range(40) for p in benign_flow(rng, i * 0.2, i)]
    for i, name in enumerate(["SYN flood", "bulk exfiltration", "UDP flood"]):
        packets += ATTACKS[name](rng, 2.0 + i * 3, 100 + i)
    return sorted(packets, key=lambda p: p.timestamp)


def check_events(events):
    from_attacker = [e for e in events if e["flow"]["src_ip"] == ATTACKER_IP]
    assert sorted(e["flow"]["protocol"] for e in from_attacker) == ["TCP", "TCP", "UDP"]
    assert all(e["label"] == "malicious" for e in from_attacker), "every attack flow must be flagged"
    false_alarms = [e for e in events if e["flow"]["src_ip"] != ATTACKER_IP and e["label"] != "benign"]
    assert len(false_alarms) <= 2, "at most 5% of the 40 benign flows may be flagged"


def test_pipeline_end_to_end(tmp_path):
    pipeline = make_pipeline(tmp_path, use_mock=True)
    for pkt in traffic():
        pipeline.handle_packet(pkt)
    pipeline.flush()
    check_events(read_events(tmp_path))


def to_scapy(obs: PacketObservation):
    flags = ("S" if obs.syn_flag else "") + ("F" if obs.fin_flag else "") + ("A" if obs.ack_flag else "")
    if obs.protocol == "TCP":
        pkt = Ether() / IP(src=obs.src_ip, dst=obs.dst_ip) / TCP(sport=obs.src_port, dport=obs.dst_port, flags=flags)
        header = 14 + 20 + 20
    else:
        pkt = Ether() / IP(src=obs.src_ip, dst=obs.dst_ip) / UDP(sport=obs.src_port, dport=obs.dst_port)
        header = 14 + 20 + 8
    pkt = pkt / Raw(b"x" * max(obs.length - (header - 14), 0))
    pkt.time = 1_700_000_000 + obs.timestamp
    return pkt


def test_pcap_replay_runs_to_completion(tmp_path):
    pcap = tmp_path / "traffic.pcap"
    wrpcap(str(pcap), [to_scapy(p) for p in traffic()])
    pipeline = make_pipeline(tmp_path, pcap_path=pcap)
    pipeline.start()  # must return by itself once the file is replayed
    check_events(read_events(tmp_path))
