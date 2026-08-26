# Implementation roadmap

## Phase 1 — Foundation

- Establish Python and frontend project structure.
- Define normalized event and alert schemas.
- Add configuration and logging.
- Add a local alert sink for development.

## Phase 2 — Streaming vertical slice

- Implement JSONL replay with rate control.
- Implement window manager and metrics.
- Add port-scan and SYN-flood detectors.
- Emit schema-compliant alerts.
- Add unit tests.

## Phase 3 — Demo fixtures and dashboard

- Add and validate deterministic DNS-tunnelling and beaconing fixtures.
- Create React/Vite/TypeScript app.
- Add HeroUI/Tailwind theme.
- Build overview and live-alert views.
- Connect to a local API/realtime adapter.

## Phase 4 — Appwrite integration

- Configure authentication and permissions (documented; collection setup is manual).
- Create alert and benchmark collections (documented; collection setup is manual).
- Persist alerts with batching/backpressure (implemented: optional sink, failure counted without blocking detection).
- Subscribe to Appwrite Realtime from the dashboard (implemented: Appwrite Realtime merged with the WebSocket stream, deduplicated by `alert_id`).

## Phase 5 — Additional detection

- Add DNS tunnelling and DGA features.
- Add beacon periodicity.
- Add encrypted-session metadata features.
- Add exfiltration, UDP amplification, and Slowloris scenarios (implemented).

## Phase 6 — ML and explanation

- Train and evaluate local scikit-learn models (implemented: Random Forest + Isolation Forest on 15 window features, saved as versioned artifacts).
- Version model artifacts (implemented as `ml-v1`).
- Add anomaly score to alerts (implemented as `ml_anomaly_score` evidence).
- Optionally integrate Qwen2.5-3B-Instruct through Ollama asynchronously (implemented: explanation worker, `explained` WebSocket messages, on-demand endpoint, dashboard drawer states).
- Keep deterministic fallback explanations (implemented: rules-only mode without artifacts and template explanations when Ollama is offline).

## Phase 7 — Evaluation and presentation

- Run throughput and latency benchmarks.
- Document precision/recall and limitations.
- Verify no payload decryption or response path.
- Package Docker Compose demo.
- Rehearse the evaluator walkthrough.
