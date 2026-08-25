# Project plan

## Objective

Deliver a laptop-runnable SIH26145 prototype that demonstrates passive, streaming cyber-threat detection over replayed unidirectional IP metadata.

## Workstreams

### Detection engine

Build normalized event models, replay ingestion, windowed state, features, detectors, model loading, alert generation, metrics, and local buffering.

### Application services

Configure Appwrite collections, permissions, authentication, alert persistence, Realtime subscriptions, and optional file storage. Add a small FastAPI control/metrics API if needed.

### Frontend

Build a dark security dashboard with HeroUI and Tailwind. Add overview metrics, live alerts, details/evidence, charts, replay controls, and connection/error states.

### Dataset and evaluation

Create safe deterministic fixtures for benign traffic and attack patterns. Keep labels separate. Measure throughput, latency, and detection quality.

### Documentation and presentation

Maintain architecture, threat-model, setup, demo script, limitations, and benchmark documentation. Prepare a concise evaluator walkthrough.

## Milestones

1. Repository and documentation baseline.
2. Event/alert schemas and local fixture replay.
3. Port-scan and SYN-flood vertical slice.
4. Local alert API/storage adapter.
5. Dashboard with live alert feed.
6. Appwrite persistence and Realtime.
7. DNS tunnelling and beaconing detectors.
8. Remaining detectors and optional ML models.
9. Optional Ollama explanation layer.
10. Tests, benchmarks, packaging, and SIH demo rehearsal.

## Definition of done

- A clean setup command starts the demo.
- A selected fixture replays incrementally.
- At least three threat scenarios create correct, explainable alerts.
- Dashboard updates live.
- The system demonstrates no return path and no payload decryption.
- Tests and benchmark results are documented.
- Secrets and private data are excluded from Git.
