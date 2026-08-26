# Architecture

## High-level design

```text
Synthetic traffic generator / fixture
              │
              ▼
      Read-only JSONL replay
              │
              ▼
      Python streaming worker
       ├── event validation
       ├── keyed window state
       ├── feature extraction
       ├── rule detectors
       ├── local ML inference
       └── alert construction
              │
              ├── Appwrite Databases (persistence)
              ├── Appwrite Realtime (dashboard delivery)
              └── FastAPI control/metrics API + WebSocket stream
                              │
                              ▼
                 React + TypeScript dashboard
```

## Components

### Traffic fixtures and replay

The fixture generator creates benign and attack-labeled events. The replay adapter emits them at a controlled rate. Ground-truth labels are used for evaluation and are never provided to the detector during inference.

### Python detection worker

The worker is the security-critical component. It accepts events, validates their shape, updates bounded state, computes features, invokes detectors, and emits alerts. It has no client capable of sending traffic to observed hosts.

### Feature extraction

Features are computed over individual events and sliding windows. State is keyed by source, destination, service, fingerprint, or other behavior-specific keys. Window sizes are detector-specific, typically 5 seconds for floods, 30 seconds for scanning/beaconing, and 1–5 minutes for exfiltration baselines.

### Detection layer

A hybrid layer combines deterministic rules, statistical tests, and local scikit-learn models. Rules provide evidence and reliable behavior for known patterns. ML supplies anomaly scores and classification support.

### Appwrite application services

Appwrite stores alert documents, manages authenticated users, stores optional replay files, and broadcasts alert changes through Realtime. It is part of the application/control plane, not the observed network path.

### FastAPI service

FastAPI exposes local control and metrics endpoints, starts/stops replay, serves historical alerts, and streams alerts over WebSocket. It does not probe or control observed network devices.

### Explanation worker (optional)

An async worker probes Ollama on startup and, for each emitted alert, requests a short plain-language explanation from a local model (default `qwen2.5:3b-instruct`). Explanations arrive asynchronously as `explained` WebSocket messages and update the alert drawer in place. Ollama outages fall back to a deterministic template; detection is never blocked.

### Dashboard

The React dashboard subscribes to new alerts over the local WebSocket stream and, when configured, over Appwrite Realtime (deduplicated by `alert_id`). It loads stored alerts from Appwrite on startup, displays metrics and timelines, and provides alert investigation and replay controls. It does not make detection decisions.

## Data flow guarantees

1. Ingest is append-only/read-only from the detector's perspective.
2. Detection operates on metadata and derived features.
3. Alerts are generated without contacting sources or destinations.
4. Persistence and dashboard delivery happen after detection; WebSocket delivery remains the primary stream and Appwrite Realtime is a deduplicated secondary.
5. An Appwrite or LLM outage must not prevent local detection and local alert buffering.

## Failure handling

- Invalid events are rejected and counted.
- Detector errors are isolated per event/window where possible.
- Alerts are buffered locally before remote persistence.
- The dashboard shows stale/disconnected status.
- LLM explanation failure falls back to a deterministic template.

## Deployment modes

### SIH demo mode

All services run locally using Docker Compose or local processes. JSONL replay produces deterministic scenarios.

### Future collector mode

A flow exporter or PCAP adapter feeds the same normalized event interface. Detection logic remains unchanged.
