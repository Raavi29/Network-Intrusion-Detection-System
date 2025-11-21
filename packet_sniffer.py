from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable

from rich import print

try:
    from scapy.all import IP, TCP, UDP, ICMP, sniff  # type: ignore
except Exception:  # pragma: no cover - scapy might be missing during tests
    IP = TCP = UDP = ICMP = sniff = None  # type: ignore

try:
    import pyshark  # type: ignore
except Exception:  # pragma: no cover
    pyshark = None  # type: ignore


@dataclass(slots=True)
class PacketObservation:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    syn_flag: bool = False
    fin_flag: bool = False
    ack_flag: bool = False


class PacketSource:
    def start(self, handler: Callable[[PacketObservation], None]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def stop(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class ScapyPacketSource(PacketSource):
    def __init__(self, interface: str | None, bpf_filter: str | None, snaplen: int, promisc: bool) -> None:
        if sniff is None:
            raise RuntimeError("scapy is not installed")
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promisc = promisc
        self._sniff_thread: threading.Thread | None = None

    def start(self, handler: Callable[[PacketObservation], None]) -> None:
        def _on_packet(pkt):
            obs = self._to_observation(pkt)
            if obs:
                handler(obs)

        self._sniff_thread = threading.Thread(
            target=sniff,
            kwargs={
                "iface": self.interface,
                "prn": _on_packet,
                "filter": self.bpf_filter,
                "store": False,
                "promisc": self.promisc,
                "count": 0,
                "timeout": None,
                "lfilter": None,
                "opened_socket": None,
                "session": None,
                "stop_filter": None,
                "started_callback": None,
                "iface_hint": None,
                "offline": None,
                "monitor": False,
                "pkt_count": 0,
            },
            daemon=True,
        )
        print(f"[bold cyan]Starting live capture[/] on interface={self.interface or 'default'} filter={self.bpf_filter or 'any'}")
        self._sniff_thread.start()

    def stop(self) -> None:
        # Scapy sniff runs until process exits; rely on external signal.
        print("[yellow]Stopping scapy capture (requires process shutdown)[/]")

    @staticmethod
    def _to_observation(pkt) -> PacketObservation | None:
        if IP is None or not pkt.haslayer(IP):
            return None
        ip_layer = pkt[IP]
        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        syn = fin = ack = False

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            flags = pkt[TCP].flags
            syn = bool(flags & 0x02)
            fin = bool(flags & 0x01)
            ack = bool(flags & 0x10)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        return PacketObservation(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(pkt),
            syn_flag=syn,
            fin_flag=fin,
            ack_flag=ack,
        )


class PCAPPacketSource(PacketSource):
    def __init__(self, pcap_path: str):
        if pyshark is None:
            raise RuntimeError("pyshark is not installed")
        self.pcap_path = pcap_path

    def start(self, handler: Callable[[PacketObservation], None]) -> None:
        print(f"[bold cyan]Replaying[/] packets from {self.pcap_path}")
        capture = pyshark.FileCapture(self.pcap_path)
        for pkt in capture:
            try:
                obs = PacketObservation(
                    timestamp=datetime.fromisoformat(pkt.sniff_time.isoformat()).timestamp(),
                    src_ip=pkt.ip.src,
                    dst_ip=pkt.ip.dst,
                    src_port=int(getattr(pkt[pkt.transport_layer], "srcport", 0)),
                    dst_port=int(getattr(pkt[pkt.transport_layer], "dstport", 0)),
                    protocol=pkt.transport_layer or pkt.highest_layer,
                    length=int(pkt.length),
                    syn_flag=int(getattr(pkt.tcp, "flags_syn", 0)) == 1 if "TCP" in pkt else False,
                    fin_flag=int(getattr(pkt.tcp, "flags_fin", 0)) == 1 if "TCP" in pkt else False,
                    ack_flag=int(getattr(pkt.tcp, "flags_ack", 0)) == 1 if "TCP" in pkt else False,
                )
                handler(obs)
            except AttributeError:
                continue

    def stop(self) -> None:
        print("[yellow]PCAP replay finished[/]")


class MockPacketSource(PacketSource):
    """Generates synthetic packets for environments without capture privileges."""

    def __init__(self, rate_per_sec: int = 50):
        self.rate = rate_per_sec
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self, handler: Callable[[PacketObservation], None]) -> None:
        self._running = True

        def _loop():
            while self._running:
                handler(self._random_packet())
                time.sleep(1 / self.rate)

        self._thread = threading.Thread(target=_loop, daemon=True)
        print(f"[bold cyan]Starting mock traffic generator[/] rate={self.rate}/s")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        print("[yellow]Mock packet source stopped[/]")

    def _random_packet(self) -> PacketObservation:
        now = time.time()
        src_ip = f"192.168.1.{random.randint(2, 200)}"
        dst_ip = random.choice(["10.0.0.5", "10.0.0.10", "172.16.0.2"])
        syn = random.random() < 0.1
        return PacketObservation(
            timestamp=now,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([22, 80, 443, 3389]),
            protocol=random.choice(["TCP", "UDP"]),
            length=random.randint(60, 1500),
            syn_flag=syn,
            fin_flag=random.random() < 0.05 if syn else False,
            ack_flag=not syn,
        )


def build_packet_source(
    interface: str | None,
    bpf_filter: str | None,
    snaplen: int,
    promisc: bool,
    pcap_path: str | None,
    use_mock: bool,
) -> PacketSource:
    if use_mock:
        return MockPacketSource()
    if pcap_path:
        return PCAPPacketSource(pcap_path)
    return ScapyPacketSource(interface, bpf_filter, snaplen, promisc)

