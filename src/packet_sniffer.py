from __future__ import annotations

import heapq
import itertools
import os
import random
import threading
import time
from typing import Callable

from rich import print

from .packets import PacketObservation
from .traffic import ATTACKS, benign_flow

try:
    from scapy.all import ICMP, IP, TCP, UDP, AsyncSniffer, PcapReader  # type: ignore
except Exception:  # pragma: no cover - scapy might be missing during tests
    IP = TCP = UDP = ICMP = AsyncSniffer = PcapReader = None  # type: ignore

__all__ = ["PacketObservation", "PacketSource", "ScapyPacketSource", "PCAPPacketSource", "MockPacketSource", "build_packet_source"]


class PacketSource:
    # A blocking source finishes inside start() (a PCAP replay). A live source keeps running.
    blocking = False

    def start(self, handler: Callable[[PacketObservation], None]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def stop(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def failure(self) -> Exception | None:
        """Return the error that killed a running capture, or None while it is healthy."""
        return None


def packet_to_observation(pkt) -> PacketObservation | None:
    """Convert a scapy packet to a PacketObservation. Returns None for non-IP packets."""
    if IP is None or not pkt.haslayer(IP):
        return None
    ip_layer = pkt[IP]
    protocol = "OTHER"
    src_port = dst_port = 0
    syn = fin = ack = False
    if pkt.haslayer(TCP):
        protocol = "TCP"
        src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
        flags = int(pkt[TCP].flags)
        syn, fin, ack = bool(flags & 0x02), bool(flags & 0x01), bool(flags & 0x10)
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
    return PacketObservation(
        timestamp=float(pkt.time),
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


class ScapyPacketSource(PacketSource):
    """Live capture with scapy. Needs root or Administrator rights."""

    def __init__(self, interface: str | None, bpf_filter: str | None, snaplen: int, promisc: bool) -> None:
        if AsyncSniffer is None:
            raise RuntimeError("scapy is not installed")
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promisc = promisc
        self._sniffer = None

    def start(self, handler: Callable[[PacketObservation], None]) -> None:
        def _on_packet(pkt) -> None:
            obs = packet_to_observation(pkt)
            if obs:
                handler(obs)

        kwargs = {"prn": _on_packet, "store": False, "promisc": self.promisc}
        if self.interface:
            kwargs["iface"] = self.interface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter
        self._sniffer = AsyncSniffer(**kwargs)
        print(f"[bold cyan]Starting live capture[/] on interface={self.interface or 'default'} filter={self.bpf_filter or 'any'}")
        self._sniffer.start()
        # scapy reports a failed start (no permission, bad interface, no libpcap for the
        # filter) only inside its background thread, so wait for it to settle and re-raise.
        # `running` turns True before the error appears, so watch for an exception for a short grace period.
        deadline = time.time() + 1.0
        while time.time() < deadline and self._sniffer.exception is None:
            time.sleep(0.05)
        self._raise_if_failed()

    def failure(self) -> Exception | None:
        return self._sniffer.exception if self._sniffer is not None else None

    def _raise_if_failed(self) -> None:
        error = self.failure()
        if error is not None:
            raise RuntimeError(f"live capture failed: {error}") from error

    def stop(self) -> None:
        if self._sniffer is not None and self._sniffer.running:
            try:
                self._sniffer.stop()
            except Exception:  # scapy re-raises a capture error here; start() or failure() already reported it
                pass
        print("[yellow]Live capture stopped[/]")


class PCAPPacketSource(PacketSource):
    """Replays a PCAP file with scapy (no tshark needed) using the capture's own timestamps."""

    blocking = True

    def __init__(self, pcap_path: str):
        if PcapReader is None:
            raise RuntimeError("scapy is not installed")
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        self.pcap_path = pcap_path

    def start(self, handler: Callable[[PacketObservation], None]) -> None:
        print(f"[bold cyan]Replaying[/] packets from {self.pcap_path}")
        with PcapReader(self.pcap_path) as reader:
            for pkt in reader:
                obs = packet_to_observation(pkt)
                if obs:
                    handler(obs)

    def stop(self) -> None:
        print("[yellow]PCAP replay finished[/]")


class MockPacketSource(PacketSource):
    """Generates synthetic traffic made of whole flows, with an occasional attack, in real time.

    Use it to try the IDS without capture privileges. About `attack_rate` of the flows are attacks.
    """

    def __init__(self, flows_per_sec: float = 1.5, attack_rate: float = 0.05, seed: int | None = None):
        self.flows_per_sec = flows_per_sec
        self.attack_rate = attack_rate
        self.rng = random.Random(seed)
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self, handler: Callable[[PacketObservation], None]) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._loop, args=(handler,), daemon=True)
        print(f"[bold cyan]Starting mock traffic generator[/] flows/s={self.flows_per_sec} attack_rate={self.attack_rate}")
        self._thread.start()

    def _loop(self, handler: Callable[[PacketObservation], None]) -> None:
        pending: list = []
        order = itertools.count()
        next_flow_at = time.time()
        flow_id = 0
        attacks = list(ATTACKS.values())
        while self._running:
            now = time.time()
            while now >= next_flow_at:
                make = self.rng.choice(attacks) if self.rng.random() < self.attack_rate else benign_flow
                for pkt in make(self.rng, next_flow_at, flow_id):
                    heapq.heappush(pending, (pkt.timestamp, next(order), pkt))
                flow_id += 1
                next_flow_at += self.rng.expovariate(self.flows_per_sec)
            while pending and pending[0][0] <= now:
                handler(heapq.heappop(pending)[2])
            time.sleep(0.005)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        print("[yellow]Mock packet source stopped[/]")


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
