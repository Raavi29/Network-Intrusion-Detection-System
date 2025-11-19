from __future__ import annotations

import time
from typing import Callable, Dict

from rich.console import Console

from .alerts import AlertManager
from .config import AppConfig
from .feature_engineer import FeatureEngineer
from .model import ModelManager, PredictionResult
from .packet_sniffer import PacketObservation, build_packet_source
from .storage import EventStore

console = Console()


class DetectionPipeline:
    def __init__(self, config: AppConfig):
        self.config = config
        self.feature_engineer = FeatureEngineer(
            flow_timeout_s=self.config.features.flow_timeout_s,
            max_flows=self.config.features.max_flows,
            emit_after_packets=self.config.features.emit_after_packets,
        )
        self.model_manager = ModelManager(config.model)
        self.alert_manager = AlertManager(config.alerts)
        self.event_store = EventStore(config.model.artifact_dir / "events.jsonl")
        self.packet_source = build_packet_source(
            interface=self.config.sniffer.interface,
            bpf_filter=self.config.sniffer.bpf_filter,
            snaplen=self.config.sniffer.snaplen,
            promisc=self.config.sniffer.promisc,
            pcap_path=str(self.config.sniffer.pcap_path) if self.config.sniffer.pcap_path else None,
            use_mock=self.config.sniffer.use_mock,
        )

    def start(self) -> None:
        console.print("[bold green]Loading anomaly model...[/]")
        self.model_manager.load_or_train()
        console.print("[bold green]Model ready. Starting packet pipeline.[/]")
        self.packet_source.start(self._handle_packet)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("[yellow]Stopping pipeline[/]")
            self.packet_source.stop()

    def _handle_packet(self, packet: PacketObservation) -> None:
        results = self.feature_engineer.process_packet(packet)
        for result in results:
            features = result["features"]
            metadata = result["metadata"]
            prediction = self.model_manager.predict(features, metadata)
            event = self._build_event(prediction, features)
            self.event_store.append(event)
            if prediction.label != "benign":
                self.alert_manager.send("IDS Alert", event)

    def _build_event(self, prediction: PredictionResult, features: Dict[str, float]) -> Dict[str, object]:
        return {
            "timestamp": time.time(),
            "label": prediction.label,
            "score": round(prediction.score, 4),
            "flow": prediction.metadata,
            "features": features,
        }
