from __future__ import annotations

import argparse

from src.config import AppConfig
from src.pipeline import DetectionPipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI-Powered Intrusion Detection System")
    parser.add_argument("--interface", help="Network interface to sniff", default=None)
    parser.add_argument("--bpf", help="BPF filter expression", default=None)
    parser.add_argument("--pcap", help="Replay packets from PCAP file", default=None)
    parser.add_argument("--mock", help="Use synthetic traffic", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = AppConfig.resolve()
    if args.interface:
        config.sniffer.interface = args.interface
    if args.bpf:
        config.sniffer.bpf_filter = args.bpf
    if args.pcap:
        config.sniffer.pcap_path = args.pcap
    if args.mock:
        config.sniffer.use_mock = True
    pipeline = DetectionPipeline(config)
    pipeline.start()


if __name__ == "__main__":
    main()

