# Technology stack

## Backend and detection

| Technology | Role |
|---|---|
| Python | Traffic processing, features, detectors, ML inference |
| FastAPI | Optional control, query, health, and metrics API |
| Pydantic | Event and alert validation |
| NumPy | Numerical feature calculations |
| SciPy | Statistical and signal-processing utilities where needed |
| scikit-learn | Local anomaly detection and threat classification |
| joblib | Persisting trained model artifacts |

The initial input format is JSONL because it is simple, replayable, inspectable, and sufficient to prove streaming behavior. A PCAP adapter can be added without changing the normalized event contract.

## Application backend

| Technology | Role |
|---|---|
| Appwrite Auth | User authentication and sessions |
| Appwrite Databases | Alert and benchmark persistence |
| Appwrite Realtime | Live alert delivery to the dashboard |
| Appwrite Storage | Optional PCAP, fixture, and report files |

Appwrite does not perform packet analysis. The Python worker remains responsible for detection.

## Frontend

| Technology | Role |
|---|---|
| React | Component-based web application |
| TypeScript | Type-safe frontend code and data contracts |
| Vite | Development server and production build |
| HeroUI | Accessible dashboard components |
| Tailwind CSS | Layout and custom styling |
| Recharts | Metrics and threat visualizations |
| React Router | Dashboard navigation |
| Appwrite Web SDK | Authentication, database queries, and Realtime subscriptions |

## Optional local LLM

Use **Qwen2.5-3B-Instruct** through **Ollama** as an asynchronous explanation layer. It receives sanitized structured alert data only. It does not classify traffic, override confidence, inspect payloads, or take network actions.

The application must work without Ollama. A deterministic explanation template is the fallback.

## Development and operations

| Technology | Role |
|---|---|
| Docker Compose | Reproducible local services |
| pytest | Python tests |
| Vitest | Frontend unit tests |
| React Testing Library | Frontend component tests |
| Ruff | Python linting/formatting |
| ESLint/Prettier | TypeScript linting/formatting |

## Why this stack

The stack keeps data science and networking in Python, gives the operator a familiar browser UI, uses Appwrite for application concerns, and avoids requiring external AI APIs. It is fast to build, demonstrable on a laptop, and compatible with the statement's passive/read-only constraints.
