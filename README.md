# SIH26145 — Passive AI Cyber-Threat Detection

A reproducible Smart India Hackathon 2026 prototype for detecting cyber threats in unidirectional IP traffic using passive, read-only analysis.

> **Project status:** Full local demo implemented and tested — detection engine, FastAPI replay API with WebSocket alerts, React/HeroUI dashboard, nine threat scenarios, local scikit-learn model layer, and benchmarked throughput/latency. Appwrite persistence and an optional Ollama explanation layer are implemented as adapters.

## What are we building?

SIH26145 is a cybersecurity software system with a web dashboard. A local Python detection engine replays or ingests synthetic network-flow events, extracts behavioral features, detects threats, and emits explainable alerts. A React/TypeScript dashboard presents those alerts in near real time.

```text
Synthetic traffic → read-only replay → Python detection engine
                                      ↓
                              structured alerts
                                      ↓
                         Appwrite storage/realtime
                                      ↓
                           React security dashboard
```

The prototype simulates a secure monitoring enclave. It does not claim to implement a physical data diode.

## Goals

- Detect DDoS (SYN floods, UDP amplification, Slowloris), botnet beaconing, DGA/DNS tunnelling, encrypted-session anomalies, reconnaissance, and data exfiltration.
- Process events incrementally with bounded latency.
- Analyze TLS/QUIC using metadata only; never decrypt payloads.
- Never probe, re-contact, block, or issue commands to the observed network.
- Produce standardized, explainable alerts.
- Demonstrate a defined throughput and latency target with replayable scenarios.

## Documentation

- [Project plan](docs/PROJECT_PLAN.md)
- [Problem interpretation and scope](docs/PROBLEM_AND_SCOPE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Technology stack](docs/TECH_STACK.md)
- [Detection and ML plan](docs/DETECTION_AND_ML.md)
- [Dataset and demo scenarios](docs/DATASET_AND_DEMO.md)
- [Alert schema](docs/ALERT_SCHEMA.md)
- [Frontend plan](docs/FRONTEND.md)
- [Security constraints](docs/SECURITY.md)
- [Testing and benchmarks](docs/TESTING.md)
- [Implementation roadmap](docs/ROADMAP.md)
- [Local demo guide](docs/LOCAL_DEMO.md)

## Stack

| Area | Technology |
|---|---|
| Detection engine | Python |
| API/control plane | FastAPI |
| Packet/flow replay | JSONL initially; PCAP adapter later |
| Features and ML | Rule-based detectors plus a trained scikit-learn RandomForest layer (NumPy/SciPy features) |
| Alert validation | Pydantic |
| Application backend | Appwrite |
| Frontend | React, TypeScript, Vite |
| UI components | HeroUI + Tailwind CSS |
| Charts | Recharts |
| Local explanation model | Optional Qwen2.5-3B-Instruct through Ollama |
| Deployment | Docker Compose |
| Testing | pytest, Vitest, React Testing Library |

## Demo principle

The primary detection path remains local and deterministic/measurable. The optional small local LLM only explains already-generated structured alerts; it does not make or change detection decisions.

## Run the local demo

### Option A: local processes

```bash
python -m pip install -e 'backend[test]'
uvicorn sih_detector.api:app --app-dir backend/src --reload
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`, select a scenario, and start replay. The dashboard uses the local API and WebSocket by default. No network capture, Appwrite credentials, or external AI API is required.

### Option B: Docker Compose

```bash
docker compose up
```

The same dashboard is available at `http://localhost:5173`.

## License

To be decided by the project team before implementation/distribution.
