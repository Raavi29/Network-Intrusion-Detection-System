"""Synthetic traffic made of complete flows.

Used by the mock packet source (demo without capture privileges), the tests and
the evaluation script. Every function returns packets with absolute timestamps,
so callers decide whether to replay them in real time or all at once.
"""
from __future__ import annotations

import random
from typing import Callable, Dict, List

from .packets import PacketObservation

ATTACKER_IP = "203.0.113.9"  # TEST-NET-3 address, never routable
SERVER_IPS = ["10.0.0.5", "10.0.0.10", "172.16.0.2"]
SERVER_PORTS = [22, 80, 443, 3389]


def _client(flow_id: int) -> tuple[str, int]:
    return f"192.168.1.{2 + flow_id % 200}", 20000 + flow_id % 40000


def benign_flow(rng: random.Random, start: float, flow_id: int) -> List[PacketObservation]:
    """An ordinary client/server exchange: 12 to 32 packets over 1 to 6 seconds."""
    src_ip, src_port = _client(flow_id)
    dst_ip, dst_port = rng.choice(SERVER_IPS), rng.choice(SERVER_PORTS)
    tcp = rng.random() < 0.7
    n = rng.randint(12, 32)
    duration = rng.uniform(1.0, 6.0)
    packets: List[PacketObservation] = []
    t = start
    for k in range(n):
        if k:
            t += duration / (n - 1) * rng.uniform(0.7, 1.3)
        packets.append(
            PacketObservation(
                timestamp=t,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol="TCP" if tcp else "UDP",
                length=int(min(max(rng.gauss(450, 150), 60), 1500)),
                syn_flag=tcp and k == 0,
                fin_flag=tcp and k == n - 1 and rng.random() < 0.5,
                ack_flag=tcp and k > 0 and rng.random() < 0.6,
            )
        )
    return packets


def _burst(
    start: float,
    flow_id: int,
    n: int,
    duration: float,
    length: int,
    protocol: str,
    syn: bool = False,
    ack: bool = False,
) -> List[PacketObservation]:
    step = duration / max(n - 1, 1)
    return [
        PacketObservation(
            timestamp=start + i * step,
            src_ip=ATTACKER_IP,
            dst_ip="10.0.0.5",
            src_port=30000 + flow_id % 20000,
            dst_port=80 if protocol == "TCP" else 53,
            protocol=protocol,
            length=length,
            syn_flag=syn,
            ack_flag=ack,
        )
        for i in range(n)
    ]


def syn_flood(rng: random.Random, start: float, flow_id: int) -> List[PacketObservation]:
    return _burst(start, flow_id, rng.randint(200, 800), rng.uniform(0.5, 3.0), 60, "TCP", syn=True)


def bulk_exfiltration(rng: random.Random, start: float, flow_id: int) -> List[PacketObservation]:
    return _burst(start, flow_id, rng.randint(1500, 4000), rng.uniform(5.0, 15.0), 1400, "TCP", ack=True)


def udp_flood(rng: random.Random, start: float, flow_id: int) -> List[PacketObservation]:
    return _burst(start, flow_id, rng.randint(1000, 4000), rng.uniform(1.0, 4.0), 1000, "UDP")


def port_scan(rng: random.Random, start: float, flow_id: int) -> List[PacketObservation]:
    """30 SYN probes to different ports. Each probe is its own one-packet flow."""
    packets: List[PacketObservation] = []
    t = start
    for i in range(30):
        t += rng.uniform(0.15, 0.3)
        packets.append(
            PacketObservation(
                timestamp=t,
                src_ip=ATTACKER_IP,
                dst_ip="10.0.0.5",
                src_port=45000 + flow_id % 10000,
                dst_port=1000 + i,
                protocol="TCP",
                length=60,
                syn_flag=True,
            )
        )
    return packets


ATTACKS: Dict[str, Callable[[random.Random, float, int], List[PacketObservation]]] = {
    "SYN flood": syn_flood,
    "bulk exfiltration": bulk_exfiltration,
    "UDP flood": udp_flood,
    "port scan": port_scan,
}
