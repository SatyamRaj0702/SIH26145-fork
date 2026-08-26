"""Throughput and latency benchmark for the detection pipeline.

The benchmark replays a synthetic mixed-traffic stream (95% benign,
5% attack bursts from diverse sources) through a fresh detector and
measures:

- Sustained throughput (events/sec and Mbps) when events are pushed as
  fast as the pipeline can consume them.
- p50/p95/p99 per-event processing latency at a declared sustained rate.

Latency here is the detector's per-event processing time (feature
extraction + rule checks + optional ML scoring), which is the pipeline
component the SIH statement asks to bound.
"""

from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .detectors import DetectionConfig, WindowedDetector
from .model import load_scorer
from .schemas import FlowEvent

BASE_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


def _flow(index: int, *, rng: random.Random, attack: bool) -> FlowEvent:
    if attack:
        variant = rng.randrange(3)
        if variant == 0:  # SYN flood burst toward one target
            source_ip = f"198.51.100.{rng.randrange(2, 255)}"
            destination_ip = "10.0.0.10"
            destination_port = 80
            flags = ["SYN"]
            completed = False
            packets = rng.randrange(5, 25)
        elif variant == 1:  # UDP amplification to DNS
            source_ip = f"198.51.100.{rng.randrange(2, 255)}"
            destination_ip = "10.0.0.53"
            destination_port = 53
            flags = []
            completed = None
            packets = rng.randrange(40, 60)
        else:  # port scan fan-out
            source_ip = "10.0.0.91"
            destination_ip = "10.0.0.53"
            destination_port = rng.randrange(1, 1024)
            flags = []
            completed = False
            packets = 1
        protocol = "TCP" if variant != 1 else "UDP"
        direction = "outbound"
        dns_query = None
        record_type = None
    else:
        # Diverse benign sources so per-source detector queues stay small.
        source_ip = f"10.0.{rng.randrange(1, 40)}.{rng.randrange(2, 254)}"
        destination_ip = "203.0.113.10"
        destination_port = rng.choice([80, 443, 53])
        flags = []
        completed = True
        packets = rng.randrange(1, 4)
        protocol = "UDP" if destination_port == 53 else "TCP"
        direction = "outbound"
        dns_query = "www.example.test" if destination_port == 53 else None
        record_type = "A" if dns_query else None

    return FlowEvent(
        # Space events realistically (1 ms apart = 1,000 events/sec) so the
        # sliding window prunes naturally and the benchmark reflects sustained load.
        timestamp=BASE_TIME + timedelta(milliseconds=index),
        flow_id=f"bench-{index:06d}",
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=40000 + (index % 20000),
        destination_port=destination_port,
        protocol=protocol,
        packets=packets,
        bytes=packets * 64,
        direction=direction,  # type: ignore[arg-type]
        tcp_flags=flags,
        connection_completed=completed,
        dns_query=dns_query,
        dns_record_type=record_type,
    )


def generate_stream(count: int, seed: int = 7, attack_fraction: float = 0.05) -> list[FlowEvent]:
    """Synthetic mixed stream: ~95% benign web/DNS, ~5% attack bursts."""
    rng = random.Random(seed)
    return [_flow(index, rng=rng, attack=rng.random() < attack_fraction) for index in range(count)]


def _percentile(values: list[float], pct: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * pct / 100))
    return float(ordered[index])


def run_benchmark(
    event_count: int = 10_000,
    declared_rate: float = 100.0,
    warmup: int = 1_000,
    seed: int = 7,
    model_dir: Path | None = None,
) -> dict[str, object]:
    events = generate_stream(event_count, seed=seed)
    scorer = load_scorer(model_dir) if model_dir is not None else load_scorer()
    total_bytes = sum(event.bytes for event in events)

    # --- Phase 1: sustained throughput (no pacing) ---
    detector = WindowedDetector(DetectionConfig(), scorer=scorer)
    for event in events[:warmup]:
        detector.process(event)
    started = time.perf_counter()
    for event in events[warmup:]:
        detector.process(event)
    wall = max(time.perf_counter() - started, 1e-9)
    measured_events = len(events) - warmup
    sustained_events_per_second = measured_events / wall
    sustained_mbps = (total_bytes * 8) / (wall * 1_000_000)

    # --- Phase 2: latency at the declared sustained rate ---
    detector = WindowedDetector(DetectionConfig(), scorer=scorer)
    paced_latencies: list[float] = []
    interval = 1.0 / declared_rate
    for event in events[:warmup]:
        detector.process(event)
    next_deadline = time.perf_counter()
    for event in events[warmup:]:
        next_deadline += interval
        sleep = next_deadline - time.perf_counter()
        if sleep > 0:
            time.sleep(sleep)
        processing_started = time.perf_counter()
        detector.process(event)
        paced_latencies.append((time.perf_counter() - processing_started) * 1000)

    return {
        "event_count": measured_events,
        "sustained_events_per_second": round(sustained_events_per_second, 1),
        "sustained_mbps": round(sustained_mbps, 2),
        "declared_rate_events_per_second": declared_rate,
        "declared_rate_mbps": round((total_bytes * 8) / (max(measured_events / declared_rate, 1e-9) * 1_000_000), 2),
        "latency_ms": {
            "p50": round(_percentile(paced_latencies, 50), 3),
            "p95": round(_percentile(paced_latencies, 95), 3),
            "p99": round(_percentile(paced_latencies, 99), 3),
            "max": round(max(paced_latencies, default=0.0), 3),
            "mean": round(sum(paced_latencies) / len(paced_latencies), 3) if paced_latencies else 0.0,
        },
        "model": scorer.version if scorer else "rules-only",
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), indent=2))
