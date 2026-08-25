# Frontend plan

## Purpose

The frontend is a web-based security operations dashboard. It does not inspect packets or decide whether behavior is malicious; it presents results from the Python detection system.

## Stack

- React
- TypeScript
- Vite
- HeroUI
- Tailwind CSS
- Recharts
- React Router
- Appwrite Web SDK and Realtime

## Views

- `/login`: authentication.
- `/dashboard`: overview metrics, threat timeline, severity summary, and live alerts.
- `/alerts`: searchable/filterable alert table.
- `/alerts/:id`: full alert evidence and related activity.
- `/replay`: scenario selection and start/pause/stop controls.
- `/settings`: connection and display settings.

## Dashboard content

- Flows/events processed.
- Active alert count.
- Critical/high/medium/low counts.
- Current throughput.
- p95 detection latency.
- Threat distribution over time.
- Live alert feed.
- Source and destination summaries.
- Evidence feature values and detector version.

## Component approach

Use HeroUI for cards, tables, chips, drawers, modals, tabs, buttons, inputs, and progress indicators. Use Tailwind for layout and small domain-specific styling. Use Recharts for time-series and distribution charts.

Severity colors should be consistent and accessible: critical/danger, high/warning, medium/primary or warning, low/default, and healthy/success.

## Realtime behavior

Subscribe to Appwrite Realtime alert creation events. Optimistically update the live feed only from received server records. Display connection state and a stale-data warning when disconnected.

## Type safety

Define TypeScript types matching the backend alert contract. Validate external data at the boundary before rendering. Never assume optional protocol metadata exists.

## Failure behavior

The dashboard remains usable when the optional LLM is unavailable. It shows the technical evidence immediately and displays the explanation when generated. If Appwrite is unavailable, show connection status and use a local development adapter where appropriate.
