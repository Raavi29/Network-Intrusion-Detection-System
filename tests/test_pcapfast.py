import math
import random

from scapy.all import ICMP, IP, TCP, UDP, Ether, PcapReader, Raw, wrpcap

from src.packet_sniffer import packet_to_observation
from src.pcapfast import is_supported_pcap, read_pcap
from tests.test_pipeline import to_scapy
from src.traffic import ATTACKS, benign_flow


def test_fast_reader_matches_scapy_on_every_field(tmp_path):
    rng = random.Random(4)
    packets = benign_flow(rng, 0.0, 1) + ATTACKS["SYN flood"](rng, 1.0, 2)[:50] + ATTACKS["UDP flood"](rng, 2.0, 3)[:50]
    frames = [to_scapy(p) for p in packets]
    frames.append(Ether() / IP(src="10.1.1.1", dst="10.1.1.2") / ICMP() / Raw(b"ping"))  # ICMP
    frames.append(Ether() / IP(src="10.1.1.1", dst="10.1.1.2", proto=47) / Raw(b"gre"))  # other IP protocol
    frames.append(Ether(type=0x0806) / Raw(b"\x00" * 40))  # ARP-like, not IPv4
    pcap = tmp_path / "t.pcap"
    wrpcap(str(pcap), frames)

    assert is_supported_pcap(pcap)
    fast = list(read_pcap(pcap))
    with PcapReader(str(pcap)) as reader:
        slow = [packet_to_observation(p) for p in reader]
    assert len(fast) == len(slow) == len(frames)
    for a, b in zip(fast, slow):
        assert (a is None) == (b is None)
        if a is None:
            continue
        assert math.isclose(a.timestamp, b.timestamp, abs_tol=1e-5)
        for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "syn_flag", "fin_flag", "ack_flag"):
            assert getattr(a, field) == getattr(b, field), field


def test_fast_reader_is_much_faster_than_scapy(tmp_path):
    import time

    rng = random.Random(5)
    frames = [to_scapy(p) for p in ATTACKS["bulk exfiltration"](rng, 0.0, 1)[:1500]]
    pcap = tmp_path / "speed.pcap"
    wrpcap(str(pcap), frames)
    t = time.perf_counter(); n_fast = sum(1 for _ in read_pcap(pcap)); fast = time.perf_counter() - t
    t = time.perf_counter()
    with PcapReader(str(pcap)) as reader:
        n_slow = sum(1 for p in reader if packet_to_observation(p))
    slow = time.perf_counter() - t
    assert n_fast == n_slow == len(frames)
    assert fast * 5 < slow


def test_pcapng_is_not_claimed_as_supported(tmp_path):
    path = tmp_path / "x.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    assert not is_supported_pcap(path)
