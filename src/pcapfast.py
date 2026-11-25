"""A fast reader for classic PCAP files (Ethernet, IPv4).

scapy builds a full protocol tree for every packet, about 1,000 packets per second here, which makes
replaying a day of CIC-IDS2017 (tens of millions of packets) impractical. This reader decodes only the
fields the IDS uses. It gives the same PacketObservation as the scapy path (see tests/test_pcapfast.py).

Not handled: pcapng files, IPv6 and non-Ethernet link types. The caller falls back to scapy for those.
"""
from __future__ import annotations

import socket
import struct
from pathlib import Path
from typing import Iterator, Optional

from .packets import PacketObservation

# magic number -> (struct byte order, seconds per timestamp tick)
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
_ETHERNET = 1


def is_supported_pcap(path: str | Path) -> bool:
    """True for a classic PCAP with Ethernet frames."""
    try:
        with open(path, "rb") as f:
            head = f.read(24)
    except OSError:
        return False
    if len(head) < 24 or head[:4] not in _MAGICS:
        return False
    order = _MAGICS[head[:4]][0]
    return struct.unpack(order + "I", head[20:24])[0] & 0x0FFFFFFF == _ETHERNET


def read_pcap(path: str | Path) -> Iterator[Optional[PacketObservation]]:
    """Yield one entry per packet in the file: a PacketObservation, or None if it is not IPv4."""
    with open(path, "rb", buffering=1 << 20) as f:
        head = f.read(24)
        if len(head) < 24 or head[:4] not in _MAGICS:
            raise ValueError(f"{path} is not a classic PCAP file")
        order, tick = _MAGICS[head[:4]]
        if struct.unpack(order + "I", head[20:24])[0] & 0x0FFFFFFF != _ETHERNET:
            raise ValueError(f"{path} does not contain Ethernet frames")
        record = struct.Struct(order + "IIII")
        while True:
            header = f.read(16)
            if len(header) < 16:
                return
            seconds, fraction, captured, _original = record.unpack(header)
            data = f.read(captured)
            if len(data) < captured:
                return  # truncated file
            yield _decode(data, seconds + fraction * tick)


def _decode(data: bytes, timestamp: float) -> Optional[PacketObservation]:
    n = len(data)
    if n < 34:
        return None
    ethertype = (data[12] << 8) | data[13]
    offset = 14
    while ethertype in (0x8100, 0x88A8):  # VLAN tags
        if n < offset + 4:
            return None
        ethertype = (data[offset + 2] << 8) | data[offset + 3]
        offset += 4
    if ethertype != 0x0800 or n < offset + 20:
        return None
    first = data[offset]
    header_len = (first & 0x0F) * 4
    if first >> 4 != 4 or header_len < 20 or n < offset + header_len:
        return None
    proto = data[offset + 9]
    src_ip = socket.inet_ntoa(data[offset + 12 : offset + 16])
    dst_ip = socket.inet_ntoa(data[offset + 16 : offset + 20])
    fragment_offset = ((data[offset + 6] & 0x1F) << 8) | data[offset + 7]
    transport = offset + header_len

    protocol, sport, dport = "OTHER", 0, 0
    syn = fin = ack = False
    if fragment_offset == 0:  # later fragments carry no transport header
        if proto == 6 and n >= transport + 14:
            protocol = "TCP"
            sport = (data[transport] << 8) | data[transport + 1]
            dport = (data[transport + 2] << 8) | data[transport + 3]
            flags = data[transport + 13]
            syn, fin, ack = bool(flags & 0x02), bool(flags & 0x01), bool(flags & 0x10)
        elif proto == 17 and n >= transport + 8:
            protocol = "UDP"
            sport = (data[transport] << 8) | data[transport + 1]
            dport = (data[transport + 2] << 8) | data[transport + 3]
        elif proto == 1:
            protocol = "ICMP"
    return PacketObservation(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=sport,
        dst_port=dport,
        protocol=protocol,
        length=n,
        syn_flag=syn,
        fin_flag=fin,
        ack_flag=ack,
    )
