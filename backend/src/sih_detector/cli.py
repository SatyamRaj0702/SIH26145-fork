from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detectors import DetectionConfig, WindowedDetector
from .model import load_scorer
from .replay import read_events, replay


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay passive SIH26145 flow events")
    parser.add_argument("input", type=Path, nargs="?", default=None, help="JSONL file containing normalized flow events")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between events in seconds")
    parser.add_argument("--syn-rate", type=float, default=1000.0, help="SYN flood packet/sec threshold")
    parser.add_argument("--scan-ports", type=int, default=20, help="Port-scan unique-port threshold")
    parser.add_argument("--model-dir", type=Path, default=None, help="Directory with trained model artifacts")
    parser.add_argument(
        "--train",
        action="store_true",
        help="Train the local scikit-learn models on synthetic data and exit",
    )
    parser.add_argument("--per-class", type=int, default=200, help="Samples per class for training")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for training")
    parser.add_argument("--eval-seed", type=int, default=None, help="Random seed for scenario-separated evaluation (defaults to seed + 1000)")
    parser.add_argument("--eval-per-class", type=int, default=None, help="Evaluation samples per class (defaults to --per-class)")
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run the throughput/latency benchmark and exit",
    )
    parser.add_argument("--benchmark-events", type=int, default=20_000, help="Events for the benchmark")
    parser.add_argument("--benchmark-rate", type=float, default=10_000.0, help="Declared sustained rate for latency measurement (events/sec)")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.train:
        from .train import train_and_save

        result = train_and_save(
            output_dir=args.model_dir if args.model_dir is not None else "models",
            per_class=args.per_class,
            seed=args.seed,
            eval_seed=args.eval_seed,
            eval_per_class=args.eval_per_class,
        )
        print(json.dumps({key: value for key, value in result.items() if key != "classification_report"}))
        print(result["classification_report"])
        return

    if args.benchmark:
        from .benchmark import run_benchmark

        result = run_benchmark(
            event_count=args.benchmark_events,
            declared_rate=args.benchmark_rate,
            seed=args.seed,
            model_dir=args.model_dir,
        )
        print(json.dumps(result, indent=2))
        return

    if args.input is None:
        parser.error("input is required unless --train or --benchmark is used")
    model_dir = args.model_dir if args.model_dir is not None else Path("models")
    scorer = load_scorer(model_dir)
    detector = WindowedDetector(
        DetectionConfig(
            syn_packets_per_second=args.syn_rate,
            port_scan_unique_ports=args.scan_ports,
        ),
        scorer=scorer,
    )
    processed = replay(
        read_events(args.input),
        detector.process,
        on_alert=lambda alert: print(json.dumps(alert.model_dump(mode="json"))),
        delay_seconds=max(0.0, args.delay),
    )
    print(json.dumps({"processed_events": processed, "model": scorer.version if scorer else "rules-only"}))


if __name__ == "__main__":
    main()
