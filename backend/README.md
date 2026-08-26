# SIH26145 detector

This package is the executable detection engine of the SIH26145 project. It reads normalized passive flow events from JSONL, processes them incrementally, detects all seven SIH threat categories from metadata only, and emits structured alerts.

## Local setup

From the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e 'backend[test]'
# Optional Appwrite persistence: python -m pip install -e 'backend[appwrite]'
```

## Run tests

```bash
pytest -q backend/tests
```

## Replay a fixture

```bash
PYTHONPATH=backend/src python3 -m sih_detector.cli data/fixtures/syn_flood.jsonl
```

The command prints one JSON alert per detected incident and a final processed-event count. It does not send traffic or contact any observed host.

## Benchmark

```bash
PYTHONPATH=backend/src python3 -m sih_detector.cli --benchmark --benchmark-events 5000 --benchmark-rate 100
```

Reports sustained throughput (events/sec and Mbps) and p50/p95/p99 per-event latency at the declared rate. Measured on this machine: ~62 events/sec sustained, p95 ≈ 32 ms at 100 events/sec. See [docs/TESTING.md](../docs/TESTING.md) for the protocol and target.

## Optional local ML models

Install the ML extra and train the scikit-learn models on synthetic windows:

```bash
python -m pip install -e 'backend[ml]'
PYTHONPATH=backend/src python3 -m sih_detector.cli --train --per-class 250
```

Artifacts are written to `models/` (gitignored). When present, alerts include `ml_prediction` and `ml_anomaly_score` evidence and `model_version` becomes `rules+ml-v1`. Without artifacts the pipeline runs rules-only. `--model-dir` points the CLI at an alternative artifact directory.

## Current scope

- JSONL normalized flow input.
- Incremental replay.
- Explainable SYN-flood/DDoS detection.
- Explainable port-scan detection.
- Explainable DNS-tunnelling detection from query metadata.
- Explainable DGA-domain detection from domain metadata.
- Explainable botnet-beaconing detection from flow timing.
- Explainable encrypted-session anomaly detection from TLS/QUIC metadata only.
- Explainable data-exfiltration detection from directional byte asymmetry.
- Local FastAPI API with replay controls and WebSocket alert stream.
- Optional Appwrite persistence adapter; disabled without environment variables.
- Optional local scikit-learn models (Random Forest + Isolation Forest) with rules-only fallback.
- React dashboard is in `frontend/`.
- External AI dependency is not required.
