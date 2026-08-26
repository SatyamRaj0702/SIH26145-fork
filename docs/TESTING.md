# Testing and benchmarks

## Unit tests

Test independently:

- Event schema validation.
- Sliding-window state updates.
- Entropy and n-gram calculations.
- Periodicity and inter-arrival calculations.
- Fan-out and byte-ratio features.
- Each threat detector's threshold behavior.
- Confidence and severity mapping.
- Alert serialization.
- Window feature vector extraction (order and types).
- ML training reproducibility and artifact loading.
- ML scoring agreement with rule findings.
- LLM prompt sanitization and fallback explanation.

## Integration tests

Verify:

- Fixture replay reaches the detection worker.
- Alerts are persisted in Appwrite or a local adapter.
- Realtime alert updates reach the frontend.
- Replay controls start and stop correctly.
- Dashboard renders alerts with missing optional metadata.

## Scenario tests

Each fixture scenario should have expected detection outcomes. Include benign traffic to measure false positives. Keep scenario labels outside the inference payload.

## ML evaluation

Model training is evaluated **scenario-separated**: the evaluation set uses a different random seed than training (`--eval-seed`), so the model never sees training windows at evaluation time. Per-class precision/recall/F1 and accuracy are reported by the train command and stored in `model_meta.json`. See [docs/DETECTION_AND_ML.md](DETECTION_AND_ML.md) for the measured table and its synthetic-data caveat.

## Frontend tests

Test alert table rendering, filters, severity chips, detail drawer/page, realtime subscription state, loading/error states, and replay controls using mocked backend data.

## Benchmark

Run the built-in benchmark with:

```bash
PYTHONPATH=backend/src python3 -m sih_detector.cli --benchmark --benchmark-events 5000 --benchmark-rate 100
```

The benchmark (`backend/src/sih_detector/benchmark.py`) generates a synthetic stream of 95% benign web/DNS traffic and 5% attack bursts from diverse sources, then measures two phases:

1. **Sustained throughput** — events are pushed as fast as the pipeline consumes them (events/sec and Mbps).
2. **Latency at the declared rate** — events are paced at `--benchmark-rate`, and per-event processing latency (feature extraction + rules + optional ML scoring) is reported as p50/p95/p99/max.

### Declared target (measured 2026-08-26, Python 3.12, scikit-learn 1.9, CPU)

| Metric | Target | Measured |
|---|---|---|
| Sustained throughput | ≥ 60 events/sec | **61.7 events/sec (~0.12 Mbps)** |
| p95 per-event latency at 100 events/sec | < 100 ms | **32.3 ms** (p50 18.4 ms, p99 39.8 ms) |
| Model | ml-v1 | 9 threat classes + benign, single-process inference |

Latency is per-event processing time, measured on the alert-heavy worst case (5% attack mix); the fixture replays used by the dashboard run far below this sustained load.

### Protocol notes

- Warm-up phase is excluded from measurement.
- Model inference is single-process (`n_jobs=1`) — multiprocessing pools are spawned per prediction and would dominate latency.
- ML scoring runs only on events where a rule fires, keeping the common no-alert path cheap.
- Sliding-window state uses bounded per-key deques, so per-event cost tracks the source's window size, not the whole stream.
- For each recorded run: hardware/OS, Python/model versions, event count, declared rate, sustained throughput, and latency percentiles (see the benchmark JSON output).

## Quality targets

Initial engineering targets:

- Deterministic fixture replay.
- No detector exceptions on valid events.
- p95 per-event latency under 100 ms at the declared sustained rate (measured 32 ms).
- No raw payload in alert or LLM explanation input.
- Every generated alert has evidence.

Detection precision/recall targets should be established after baseline fixtures exist; avoid inventing accuracy numbers.
