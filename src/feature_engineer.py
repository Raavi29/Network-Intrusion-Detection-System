from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Tuple

from .packets import PacketObservation

FlowKey = Tuple[str, str, int, int, str]
FlowResult = Dict[str, Dict[str, float | str]]


@dataclass(slots=True)
class FlowStats:
    key: FlowKey
    first_seen: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    fin_count: int = 0
    ack_count: int = 0
    lengths: List[int] = field(default_factory=list)
    inter_arrivals: Deque[float] = field(default_factory=lambda: deque(maxlen=50))
    _prev_time: float | None = None

    def update(self, pkt: PacketObservation) -> None:
        self.packet_count += 1
        self.byte_count += pkt.length
        self.last_seen = pkt.timestamp
        if pkt.syn_flag:
            self.syn_count += 1
        if pkt.fin_flag:
            self.fin_count += 1
        if pkt.ack_flag:
            self.ack_count += 1
        self.lengths.append(pkt.length)
        if self._prev_time is not None:
            self.inter_arrivals.append(pkt.timestamp - self._prev_time)
        self._prev_time = pkt.timestamp

    def duration(self) -> float:
        return max(self.last_seen - self.first_seen, 1e-3)

    def to_feature_vector(self) -> Dict[str, float]:
        avg_len = sum(self.lengths) / len(self.lengths) if self.lengths else 0
        std_len = (
            math.sqrt(sum((l - avg_len) ** 2 for l in self.lengths) / len(self.lengths))
            if len(self.lengths) > 1
            else 0
        )
        avg_iat = sum(self.inter_arrivals) / len(self.inter_arrivals) if self.inter_arrivals else 0
        return {
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": self.duration(),
            "pps": self.packet_count / self.duration(),
            "bps": self.byte_count * 8 / self.duration(),
            "avg_packet_len": avg_len,
            "std_packet_len": std_len,
            "syn_ratio": self.syn_count / max(self.packet_count, 1),
            "fin_ratio": self.fin_count / max(self.packet_count, 1),
            "ack_ratio": self.ack_count / max(self.packet_count, 1),
            "avg_inter_arrival": avg_iat,
            "protocol_tcp": 1.0 if self.key[4] == "TCP" else 0.0,
            "protocol_udp": 1.0 if self.key[4] == "UDP" else 0.0,
        }

    def to_metadata(self) -> Dict[str, float | str]:
        src_ip, dst_ip, src_port, dst_port, proto = self.key
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class FeatureEngineer:
    """Groups packets into one-direction flows and emits one feature vector per finished flow.

    A flow is finished when it sends a FIN or goes quiet for `flow_timeout_s`. Only flows with at
    least `min_packets` packets are scored, because the model was trained on whole flows and a
    one or two packet flow carries too little signal to judge.
    """

    SWEEP_INTERVAL_S = 0.5

    def __init__(self, flow_timeout_s: float, max_flows: int, min_packets: int):
        self.flow_timeout_s = flow_timeout_s
        self.max_flows = max_flows
        self.min_packets = min_packets
        self.flows: Dict[FlowKey, FlowStats] = {}
        self._last_sweep = float("-inf")

    def process_packet(self, pkt: PacketObservation) -> List[FlowResult]:
        outputs: List[FlowResult] = []
        key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                outputs.extend(self._evict_oldest())
            flow = FlowStats(key=key, first_seen=pkt.timestamp, last_seen=pkt.timestamp)
            self.flows[key] = flow
        flow.update(pkt)
        if pkt.fin_flag:
            outputs.extend(self._finish(key))
        if pkt.timestamp - self._last_sweep >= self.SWEEP_INTERVAL_S:
            self._last_sweep = pkt.timestamp
            outputs.extend(self._expire_old(pkt.timestamp))
        return outputs

    def flush(self) -> List[FlowResult]:
        """Finish every open flow, for the end of a PCAP or a shutdown."""
        outputs: List[FlowResult] = []
        for key in list(self.flows):
            outputs.extend(self._finish(key))
        return outputs

    def _expire_old(self, current_time: float) -> List[FlowResult]:
        outputs: List[FlowResult] = []
        for key, flow in list(self.flows.items()):
            if current_time - flow.last_seen >= self.flow_timeout_s:
                outputs.extend(self._finish(key))
        return outputs

    def _evict_oldest(self) -> List[FlowResult]:
        oldest = sorted(self.flows, key=lambda k: self.flows[k].last_seen)[: max(int(self.max_flows * 0.1), 1)]
        outputs: List[FlowResult] = []
        for key in oldest:
            outputs.extend(self._finish(key))
        return outputs

    def _finish(self, key: FlowKey) -> List[FlowResult]:
        flow = self.flows.pop(key, None)
        if flow is None or flow.packet_count < self.min_packets:
            return []
        return [{"features": flow.to_feature_vector(), "metadata": flow.to_metadata()}]
