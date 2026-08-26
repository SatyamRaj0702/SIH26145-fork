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
- React dashboard is in `frontend/`.
- External AI dependency is not required.
