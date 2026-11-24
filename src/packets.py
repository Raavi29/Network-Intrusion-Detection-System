from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PacketObservation:
    """The few packet fields the IDS needs, independent of how it was captured."""

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
