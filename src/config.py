from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os


@dataclass(slots=True)
class SnifferConfig:
    interface: str | None = os.getenv("IDS_INTERFACE")
    bpf_filter: str | None = os.getenv("IDS_BPF_FILTER")
    pcap_path: Path | None = (
        Path(os.getenv("IDS_PCAP_PATH")) if os.getenv("IDS_PCAP_PATH") else None
    )
    use_mock: bool = os.getenv("IDS_USE_MOCK", "false").lower() == "true"
    snaplen: int = int(os.getenv("IDS_SNAPLEN", "1600"))
    promisc: bool = os.getenv("IDS_PROMISC", "true").lower() == "true"


@dataclass(slots=True)
class FeatureConfig:
    flow_timeout_s: float = float(os.getenv("IDS_FLOW_TIMEOUT_S", "5"))
    max_flows: int = int(os.getenv("IDS_MAX_FLOWS", "5000"))
    min_packets: int = int(os.getenv("IDS_MIN_PACKETS", "5"))


@dataclass(slots=True)
class ModelConfig:
    artifact_dir: Path = Path(os.getenv("IDS_ARTIFACT_DIR", "artifacts"))
    baseline_path: Path | None = (
        Path(os.getenv("IDS_BASELINE_PATH")) if os.getenv("IDS_BASELINE_PATH") else None
    )
    contamination: float = float(os.getenv("IDS_MODEL_CONTAMINATION", "0.02"))
    anomaly_threshold: float = float(os.getenv("IDS_ANOMALY_THRESHOLD", "-0.05"))


@dataclass(slots=True)
class AlertConfig:
    slack_webhook: str | None = os.getenv("IDS_SLACK_WEBHOOK")
    email_from: str | None = os.getenv("IDS_EMAIL_FROM")
    email_to: str | None = os.getenv("IDS_EMAIL_TO")
    smtp_server: str | None = os.getenv("IDS_SMTP_SERVER")
    smtp_port: int | None = (
        int(os.getenv("IDS_SMTP_PORT")) if os.getenv("IDS_SMTP_PORT") else None
    )
    smtp_username: str | None = os.getenv("IDS_SMTP_USERNAME")
    smtp_password: str | None = os.getenv("IDS_SMTP_PASSWORD")


@dataclass(slots=True)
class AppConfig:
    sniffer: SnifferConfig = field(default_factory=SnifferConfig)
    features: FeatureConfig = field(default_factory=FeatureConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)

    @staticmethod
    def resolve() -> "AppConfig":
        """Factory that ensures artifact directories exist."""
        cfg = AppConfig()
        cfg.model.artifact_dir.mkdir(parents=True, exist_ok=True)
        Path("data").mkdir(exist_ok=True)
        Path("artifacts").mkdir(exist_ok=True)
        return cfg

