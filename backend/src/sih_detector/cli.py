from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detectors import DetectionConfig, WindowedDetector
from .model import load_scorer
from .replay import read_events, replay


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process passive SIH26145 flow events")
    parser.add_argument("input", type=Path, nargs="?", default=None, help="JSONL file containing normalized flow events")
    parser.add_argument("--live", action="store_true", help="Capture live metadata from an authorized interface")
    parser.add_argument("--interface", default=None, help="Interface for --live, for example eth0")
    parser.add_argument("--bpf-filter", default="ip or ip6", help="Capture filter for --live")
    parser.add_argument("--capture-output", type=Path, default=None, help="Write normalized live events to JSONL")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between events in seconds")
    parser.add_argument("--syn-rate", type=float, default=1000.0, help="SYN flood packet/sec threshold")
    parser.add_argument("--scan-ports", type=int, default=20, help="Port-scan unique-port threshold")
    parser.add_argument("--model-dir", type=Path, default=None, help="Directory with trained model artifacts")
    parser.add_argument(
        "--train",
        action="store_true",
        help="Train the local scikit-learn models on built-in synthetic data and exit",
    )
    parser.add_argument("--train-labeled", type=Path, default=None, help="Train from labeled real-observation windows")
    parser.add_argument("--data-source", choices=("real", "bootstrap"), default="real", help="Provenance of --train-labeled data")
    parser.add_argument("--train-baseline", type=Path, default=None, help="Train an anomaly baseline from unlabeled normalized live events")
    parser.add_argument("--build-bootstrap-dataset", type=Path, default=None, help="Write a labeled development dataset from built-in fixtures")
    parser.add_argument("--import-flow-csv", type=Path, default=None, help="Import a CICFlowMeter/CICIDS-style labeled flow CSV")
    parser.add_argument("--flow-output", type=Path, default=None, help="Output JSONL for --import-flow-csv")
    parser.add_argument("--flow-window-size", type=int, default=32, help="Flows per imported training window")
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

    if args.import_flow_csv is not None:
        if args.flow_output is None:
            parser.error("--flow-output is required with --import-flow-csv")
        from .flow_dataset import import_labeled_flow_csv

        print(json.dumps(import_labeled_flow_csv(args.import_flow_csv, args.flow_output, args.flow_window_size)))
        return

    if args.build_bootstrap_dataset is not None:
        from .train import build_bootstrap_dataset

        print(json.dumps(build_bootstrap_dataset(args.build_bootstrap_dataset, per_class=args.per_class, seed=args.seed)))
        return

    if args.train_labeled is not None or args.train_baseline is not None:
        from .train import train_baseline_from_jsonl, train_from_labeled_jsonl

        if args.train_labeled is not None and args.train_baseline is not None:
            parser.error("choose only one of --train-labeled or --train-baseline")
        result = (
            train_from_labeled_jsonl(
                args.train_labeled,
                output_dir=args.model_dir or "models",
                seed=args.seed,
                training_mode="fixture_bootstrap" if args.data_source == "bootstrap" else "operator_labeled_real_observations",
            )
            if args.train_labeled is not None
            else train_baseline_from_jsonl(args.train_baseline, output_dir=args.model_dir or "models")
        )
        print(json.dumps({key: value for key, value in result.items() if key != "classification_report"}))
        if "classification_report" in result:
            print(result["classification_report"])
        return

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

    if args.input is None and not args.live:
        parser.error("input is required unless --live, --train, --benchmark, or a real-data training option is used")
    model_dir = args.model_dir if args.model_dir is not None else Path("models")
    scorer = load_scorer(model_dir)
    detector = WindowedDetector(
        DetectionConfig(
            syn_packets_per_second=args.syn_rate,
            port_scan_unique_ports=args.scan_ports,
        ),
        scorer=scorer,
    )
    output = args.capture_output.open("w", encoding="utf-8") if args.capture_output else None
    try:
        if args.live:
            import threading

            from .live_capture import capture_events

            stop_event = threading.Event()
            events = capture_events(stop_event, interface=args.interface, bpf_filter=args.bpf_filter)
        else:
            events = read_events(args.input)

        def on_event(event):
            if output is not None:
                output.write(json.dumps(event.model_dump(mode="json")) + "\n")
                output.flush()
            return detector.process(event)

        processed = replay(
            events,
            on_event,
            on_alert=lambda alert: print(json.dumps(alert.model_dump(mode="json"))),
            delay_seconds=max(0.0, args.delay),
        )
    finally:
        if output is not None:
            output.close()
    print(json.dumps({"processed_events": processed, "model": scorer.version if scorer else "rules-only"}))


if __name__ == "__main__":
    main()
