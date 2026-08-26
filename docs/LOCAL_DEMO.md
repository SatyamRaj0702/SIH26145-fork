# Local SIH demo

## What runs locally

```text
JSONL fixtures
     ↓
FastAPI replay manager
     ↓
Python read-only detectors
     ↓
WebSocket alert stream
     ↓
React + HeroUI dashboard
```

Appwrite is optional. When configured, the API also persists alerts to an Appwrite collection. Detection and the dashboard do not depend on Appwrite for the local demo.

## Start with local processes

From the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e 'backend[test]'
uvicorn sih_detector.api:app --app-dir backend/src --reload
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Start with Docker Compose

```bash
docker compose up
```

Open `http://localhost:5173`.

## Demonstration flow

1. Open the dashboard.
2. Confirm the `Realtime connected` indicator.
3. Select `syn_flood`, `port_scanning`, `dns_tunnelling`, `dga`, `beaconing`, `encrypted_session`, or `exfiltration`.
4. Choose a replay speed.
5. Start replay.
6. Watch event metrics and alerts update.
7. Select an alert row to inspect evidence.
8. Stop the replay if needed.
9. If trained, point out the active `ml-v1` model status and the `ml_prediction`/`ml_anomaly_score` evidence on an alert.
10. Explain that the input is a simulated one-way stream and the detector never sends a response.

## API endpoints

- `GET /api/health`
- `GET /api/scenarios`
- `GET /api/metrics`
- `GET /api/alerts?limit=100`
- `POST /api/replay/start`
- `POST /api/replay/stop`
- `WS /ws/alerts`

## Optional local ML models

The dashboard runs in rules-only mode without any setup. To enable model scoring:

```bash
python -m pip install -e 'backend[ml]'
PYTHONPATH=backend/src python3 -m sih_detector.cli --train --per-class 250
```

Restart the API; the metrics endpoint reports `model_status.available: true`, alerts gain `ml_prediction` and `ml_anomaly_score` evidence, and the dashboard note updates to show the active model version.

## Optional Appwrite

Install the optional SDK and set the values in `.env`:

```bash
python -m pip install -e 'backend[appwrite]'
```

Required values:

```text
APPWRITE_ENDPOINT
APPWRITE_PROJECT_ID
APPWRITE_DATABASE_ID
APPWRITE_ALERTS_COLLECTION_ID
APPWRITE_API_KEY
```

Create an alerts collection whose attributes can accept the JSON fields in [the alert schema](ALERT_SCHEMA.md). Keep Appwrite outside the simulated observed network path.

## Optional local LLM

The current dashboard uses deterministic evidence text. Qwen2.5-3B-Instruct through Ollama can be added later as an asynchronous explanation worker. It is not required to run detection or the demo.

## Troubleshooting

- `Connection refused`: start the FastAPI process on port 8000.
- No scenarios: run from the repository root so `data/fixtures` is found.
- Realtime disconnected: confirm the Vite dev server is running and the API WebSocket endpoint is available.
- Appwrite errors: unset the Appwrite variables to use local-only mode.
