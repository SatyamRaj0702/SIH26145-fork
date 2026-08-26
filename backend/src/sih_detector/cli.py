from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detectors import DetectionConfig, WindowedDetector
from .replay import read_events, replay


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay passive SIH26145 flow events")
    parser.add_argument("input", type=Path, help="JSONL file containing normalized flow events")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between events in seconds")
    parser.add_argument("--syn-rate", type=float, default=1000.0, help="SYN flood packet/sec threshold")
    parser.add_argument("--scan-ports", type=int, default=20, help="Port-scan unique-port threshold")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    detector = WindowedDetector(
        DetectionConfig(
            syn_packets_per_second=args.syn_rate,
            port_scan_unique_ports=args.scan_ports,
        )
    )
    processed = replay(
        read_events(args.input),
        detector.process,
        on_alert=lambda alert: print(json.dumps(alert.model_dump(mode="json"))),
        delay_seconds=max(0.0, args.delay),
    )
    print(json.dumps({"processed_events": processed}))


if __name__ == "__main__":
    main()
