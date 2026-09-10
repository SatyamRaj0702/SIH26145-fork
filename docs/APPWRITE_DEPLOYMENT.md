# Appwrite deployment

Appwrite is an optional application-plane persistence adapter. Detection still
runs locally and the FastAPI WebSocket remains the dashboard's live transport.
The current Next.js dashboard does not subscribe directly to Appwrite Realtime;
Appwrite stores alert history while the API delivers the active replay stream.

## 1. Create the Appwrite resources

In the Appwrite Console:

1. Create or select a project and copy its project ID.
2. Create a database and copy its database ID.
3. Create an `alerts` collection and copy its collection ID.
4. Create a server API key with only the Databases document create/read scope.
5. Add the collection attributes below.

| Attribute | Type | Required | Notes |
|---|---|---:|---|
| `timestamp` | datetime | yes | Alert event time |
| `flow_id` | string | yes | Size 256 |
| `threat_class` | string | yes | Size 64 |
| `severity` | string | yes | Size 16 |
| `confidence` | float | yes | 0 to 1 |
| `source_ip` | string | yes | Size 64 |
| `destination_ip` | string | yes | Size 64 |
| `protocol` | string | yes | Size 16 |
| `window_seconds` | integer | yes | Positive window size |
| `evidence` | string | yes | JSON-encoded evidence, size 16384 |
| `detector` | string | yes | Size 128 |
| `model_version` | string | yes | Size 64 |
| `explanation` | string | no | Size 4096 |

The backend writes `document_id = alert_id`, so no separate `alert_id`
attribute is required; Appwrite's `$id` is the alert ID. Create an index on
`timestamp` descending and another on `threat_class` if history queries are
added later.

## 2. Configure the backend

Copy the repository template and fill only the Appwrite values:

```bash
cp .env.example .env
```

```text
APPWRITE_ENDPOINT=https://cloud.appwrite.io/v1
APPWRITE_PROJECT_ID=your-project-id
APPWRITE_DATABASE_ID=your-database-id
APPWRITE_ALERTS_COLLECTION_ID=your-collection-id
APPWRITE_API_KEY=your-server-key
```

Install the optional SDK and start the API:

```bash
python -m pip install -e 'backend[appwrite]'
PYTHONPATH=backend/src uvicorn sih_detector.api:app --app-dir backend/src --reload
```

Check `/api/metrics`. A working configuration reports:

```json
{"appwrite_status":{"enabled":true,"persisted_count":0,"last_error":null}}
```

Persistence failures increment the API error count but do not stop detection or
the local WebSocket stream.

## 3. Permissions and security

- Keep the API key server-side in `.env`; never expose it as `NEXT_PUBLIC_*`.
- Give the API key only the minimum Databases permissions needed for this
  deployment.
- Keep collection document permissions closed unless a separate authenticated
  history client is explicitly implemented.
- Keep Appwrite outside the observed network path. It is application/control
  plane infrastructure, not a response path into monitored networks.
- For production, rotate the API key and use a dedicated Appwrite project.

## 4. Realtime status

The current dashboard uses `WS /ws/alerts` for active alerts and reports the
Appwrite persistence status from `/api/metrics`. Appwrite Realtime can be added
later for multi-instance history delivery, but it should be treated as a
secondary channel and deduplicated by `$id`/`alert_id`.

## 5. Smoke check

Run one replay and confirm both local delivery and persistence:

```bash
curl -X POST http://127.0.0.1:8000/api/replay/start \
  -H 'Content-Type: application/json' \
  -d '{"scenario":"syn_flood","speed":4}'

curl http://127.0.0.1:8000/api/metrics
```

Confirm that `persisted_count` increases and that the Appwrite collection
contains a document whose `$id` matches one of the emitted `alert_id` values.