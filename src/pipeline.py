from __future__ import annotations

import time
from typing import Dict

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
            min_packets=self.config.features.min_packets,
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
        self.packet_source.start(self.handle_packet)
        if self.packet_source.blocking:
            # A PCAP replay has already delivered every packet: score the flows still open and exit.
            self.flush()
            self.packet_source.stop()
            return
        try:
            while True:
                time.sleep(1)
                error = self.packet_source.failure()
                if error is not None:
                    self.packet_source.stop()
                    raise RuntimeError(f"packet capture stopped: {error}") from error
        except KeyboardInterrupt:
            console.print("[yellow]Stopping pipeline[/]")
            self.packet_source.stop()
            self.flush()

    def handle_packet(self, packet: PacketObservation) -> None:
        self._score(self.feature_engineer.process_packet(packet))

    def flush(self) -> None:
        self._score(self.feature_engineer.flush())

    def _score(self, results) -> None:
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
