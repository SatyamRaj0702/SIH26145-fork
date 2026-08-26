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

## Frontend tests

Test alert table rendering, filters, severity chips, detail drawer/page, realtime subscription state, loading/error states, and replay controls using mocked backend data.

## Benchmark protocol

For each run record:

- Hardware and operating system.
- Python/Node/model versions.
- Fixture name and event count.
- Replay rate.
- Sustained throughput.
- p50/p95 alert latency.
- CPU and memory.
- Dropped/invalid events.

Use warm-up and measured phases. Run each scenario more than once and report representative values. Do not state the target as achieved until measured.

## Quality targets

Initial engineering targets:

- Deterministic fixture replay.
- No detector exceptions on valid events.
- p95 alert latency under 2 seconds at the declared demo rate.
- No raw payload in alert or LLM explanation input.
- Every generated alert has evidence.

Detection precision/recall targets should be established after baseline fixtures exist; avoid inventing accuracy numbers.
