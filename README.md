# SIH26145 — Passive AI Cyber-Threat Detection

> **Smart India Hackathon 2026 · PS 26145 · NTRO** — AI-based detection of cyber threats in unidirectional IP traffic using passive, read-only analysis.

[![CI](https://img.shields.io/github/actions/workflow/status/Shivansh-HITK/SIH26145/ci.yml?branch=main&label=CI&logo=github)](https://github.com/Shivansh-HITK/SIH26145/actions)
[![License](https://img.shields.io/github/license/Shivansh-HITK/SIH26145)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](backend/pyproject.toml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)](backend/pyproject.toml)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?logo=nextdotjs&logoColor=white)](frontend1/package.json)

**Status:** Full local demo implemented and tested — detection engine, FastAPI replay API with WebSocket alerts, Next.js App Router console with live Google OAuth (Auth.js v5), nine threat scenarios, a local scikit-learn model layer, and benchmarked throughput/latency. Appwrite persistence and an optional Ollama explanation layer ship as adapters.

---

## Team & Institution

**College Name:** Heritage Institute of Technology, Kolkata

| Role | Name |
|---|---|
| **Team Lead** | Shivansh Kumar |
| **Team Member 1** | Satyam Raj |
| **Team Member 2** | Anshika |
| **Team Member 3** | Aditya |
| **Team Member 4** | Piyush |
| **Team Member 5** | Priyanshu |

---

## What are we building?

SIH26145 is a cybersecurity software system with a web dashboard. A local Python detection engine replays or ingests synthetic network-flow events, extracts behavioral features, detects threats, and emits explainable alerts. A Next.js/TypeScript dashboard presents those alerts in near real time.

```text
Synthetic traffic → read-only replay → Python detection engine
                                      ↓
                              structured alerts
                                      ↓
                         Appwrite storage/realtime
                                      ↓
                        Next.js security dashboard
```

The prototype simulates a secure monitoring enclave. It does not claim to implement a physical data diode.

## Dashboard

![Passive Detection Console — live dashboard](docs/screenshots/dashboard.png)

The live detection console shows scenario-driven replay controls, realtime metrics, a detection timeline, threat-class distribution, and a streaming alert table with severity, confidence, and supporting evidence for every detection.

## Features

**Threat classes detected (9):**

| Threat | Detection approach |
|---|---|
| SYN flood / volumetric DDoS | flow rate and source-IP entropy statistics |
| UDP reflection / amplification | packet rate + distinct sources toward amplification ports |
| Slowloris | held-open, incomplete connections; rate-capped to exclude floods |
| Botnet C2 beaconing | periodicity and inter-arrival analysis of repeating flows |
| DGA domains | entropy / n-gram analysis of DNS query names |
| DNS tunnelling | query length and record-type anomalies |
| Malware in encrypted sessions | TLS/QUIC metadata only — fingerprints, packet-size and timing |
| Reconnaissance / port scanning | fan-out across destination ports and hosts |
| Data exfiltration | asymmetric flow-volume and outbound/inbound byte ratios |

**Architectural guarantees:**

- Read-only ingest — never probes, re-contacts, blocks, or issues commands to the observed network.
- Metadata-only TLS/QUIC analysis — payloads are never decrypted.
- Streaming detection with bounded latency, not end-of-run batch reports.
- Standardized, explainable alerts: timestamp, flow ID, threat class, confidence, supporting evidence.
- Benchmark-verified throughput and latency (see [Testing](docs/TESTING.md)).

## Documentation

| Document | Covers |
|---|---|
| [Project plan](docs/PROJECT_PLAN.md) | Milestones and deliverables |
| [Problem interpretation & scope](docs/PROBLEM_AND_SCOPE.md) | Reading of the PS and what is in/out of scope |
| [Architecture](docs/ARCHITECTURE.md) | Pipeline and component design |
| [Technology stack](docs/TECH_STACK.md) | Languages, frameworks, tools |
| [Detection & ML](docs/DETECTION_AND_ML.md) | Detectors, features, model and evaluation |
| [Dataset & scenarios](docs/DATASET_AND_DEMO.md) | Fixtures and replay scenarios |
| [Alert schema](docs/ALERT_SCHEMA.md) | Structured alert contract |
| [Frontend](docs/FRONTEND.md) | Dashboard design |
| [Security constraints](docs/SECURITY.md) | Read-only and privacy guarantees |
| [Testing & benchmarks](docs/TESTING.md) | Test plan and measured throughput/latency |
| [Roadmap](docs/ROADMAP.md) | What's done and what's next |
| [Local demo guide](docs/LOCAL_DEMO.md) | Run it end-to-end |
| [Live capture and training](docs/LIVE_CAPTURE_AND_TRAINING.md) | Authorized passive capture and real-data model training |
| [Appwrite deployment](docs/APPWRITE_DEPLOYMENT.md) | Optional alert persistence setup and permissions |
| [SIH submission](docs/SIH_SUBMISSION.md) | Problem → solution traceability for the hackathon |

## Stack

| Area | Technology |
|---|---|
| Detection engine | Python |
| API/control plane | FastAPI |
| Packet/flow replay | JSONL initially; PCAP adapter later |
| Features and ML | Rule-based detectors plus a trained scikit-learn RandomForest layer (NumPy/SciPy features) |
| Alert validation | Pydantic |
| Application backend | Appwrite |
| Frontend | Next.js 16 (App Router), TypeScript, Auth.js v5 (Google OAuth) |
| UI & Styles | Tailwind CSS, Lucide Icons |
| Deployment | Docker Compose |
| Testing | pytest |

## Demo principle

The primary detection path remains local and deterministic/measurable. The optional small local LLM only explains already-generated structured alerts; it does not make or change detection decisions.

For authorized passive interface capture and real-data model training, see [Live capture and training](docs/LIVE_CAPTURE_AND_TRAINING.md). Unlabeled live traffic can train an anomaly baseline; supervised threat classification requires operator-labeled windows.

## Run the local demo

### Option A: local processes

```bash
python -m pip install -e 'backend[test]'
uvicorn sih_detector.api:app --app-dir backend/src --reload
```

In a second terminal:

```bash
cd frontend1
npm install
npm run dev
```

Open `http://localhost:5173`, authenticate with Google or launch replay. The dashboard uses the local API and WebSocket by default. No network capture, Appwrite credentials, or external AI API is required.

### Option B: Docker Compose

```bash
docker compose up
```

The same dashboard is available at `http://localhost:5173`.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
