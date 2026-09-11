from __future__ import annotations

import asyncio
import os
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any

from collections.abc import AsyncIterator, Iterable

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .appwrite import AppwriteAlertSink
from .detectors import DetectionConfig, WindowedDetector
from .explain import check_ollama, generate_explanation
from .incidents import IncidentAggregator
from .model import load_scorer
from .replay import read_events, replay
from .schemas import Alert


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_FIXTURE_DIR = PROJECT_ROOT / "data" / "fixtures"
DEFAULT_MODEL_DIR = PROJECT_ROOT / "models"


class ReplayRequest(BaseModel):
    scenario: str = Field(min_length=1)
    speed: float = Field(default=1.0, gt=0)


class LiveCaptureRequest(BaseModel):
    interface: str | None = Field(default=None, max_length=128)
    bpf_filter: str = Field(default="ip or ip6", min_length=1, max_length=512)


class ReplayManager:
    def __init__(
        self,
        fixture_dir: Path = DEFAULT_FIXTURE_DIR,
        model_dir: Path = DEFAULT_MODEL_DIR,
    ) -> None:
        self.fixture_dir = fixture_dir
        self.scorer = load_scorer(model_dir)
        self.model_status = {
            "available": self.scorer is not None,
            "version": self.scorer.version if self.scorer else "rules-only",
        }
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._subscribers: set[tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]] = set()
        self.alerts: deque[Alert] = deque(maxlen=500)
        self.incidents = IncidentAggregator()
        self.appwrite_sink = AppwriteAlertSink()
        self.ollama_status: dict[str, Any] = {
            "enabled": bool(os.getenv("OLLAMA_URL") or os.getenv("OLLAMA_MODEL")),
            "model": os.getenv("OLLAMA_MODEL", "qwen2.5:3b-instruct"),
            "available": False,
        }
        self.reset_metrics()

    def reset_metrics(self) -> None:
        with self._lock:
            self.metrics: dict[str, Any] = {
                "processed_events": 0,
                "alerts_generated": 0,
                "events_per_second": 0.0,
                "average_alert_latency_ms": 0.0,
                "scenario": None,
                "source_mode": "idle",
                "data_provenance": "none",
                "interface": None,
                "status": "idle",
                "running": False,
                "started_at": None,
                "finished_at": None,
                "threat_counts": {},
                "error_count": 0,
                "model_status": self.model_status,
                "appwrite_status": self.appwrite_sink.status(),
                "ollama_status": self.ollama_status,
                "incidents_generated": 0,
            }

    def scenarios(self) -> list[str]:
        return sorted(path.stem for path in self.fixture_dir.glob("*.jsonl"))

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, scenario: str, speed: float) -> None:
        if self.is_running():
            raise RuntimeError("A replay is already running")
        path = self.fixture_dir / f"{scenario}.jsonl"
        if not path.is_file() or path.parent != self.fixture_dir:
            raise FileNotFoundError(f"Unknown scenario: {scenario}")

        self._stop.clear()
        self.alerts.clear()
        self.incidents.clear()
        self.reset_metrics()
        self.metrics.update({"scenario": scenario, "status": "running", "running": True, "started_at": time.time()})
        self.metrics.update({"source_mode": "fixture", "interface": None})
        self.metrics["data_provenance"] = "synthetic_fixture"
        self._thread = threading.Thread(
            target=self._run,
            args=(path, speed),
            daemon=True,
            name="sih-replay",
        )
        self._thread.start()

    def start_live(self, interface: str | None, bpf_filter: str) -> None:
        if self.is_running():
            raise RuntimeError("A replay or live capture is already running")
        self._stop.clear()
        self.alerts.clear()
        self.incidents.clear()
        self.reset_metrics()
        self.metrics.update(
            {
                "scenario": None,
                "source_mode": "live",
                "data_provenance": "authorized_live_metadata",
                "interface": interface or "default",
                "status": "running",
                "running": True,
                "started_at": time.time(),
            }
        )
        self._thread = threading.Thread(
            target=self._run_live,
            args=(interface, bpf_filter),
            daemon=True,
            name="sih-live-capture",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        with self._lock:
            if self.metrics["status"] == "running":
                self.metrics["status"] = "stopped"
                self.metrics["running"] = False
                self.metrics["finished_at"] = time.time()

    def subscribe(self) -> tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]:
        subscription = (asyncio.get_running_loop(), asyncio.Queue(maxsize=100))
        self._subscribers.add(subscription)
        return subscription

    def unsubscribe(self, subscription: tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]) -> None:
        self._subscribers.discard(subscription)

    def _run(self, path: Path, speed: float) -> None:
        self._run_events(read_events(path), speed, "fixture")

    def _run_live(self, interface: str | None, bpf_filter: str) -> None:
        try:
            from .live_capture import capture_events

            self._run_events(capture_events(self._stop, interface, bpf_filter), 1.0, "live")
        except Exception as exc:
            with self._lock:
                self.metrics["error_count"] += 1
                self.metrics["last_error"] = str(exc)
                self.metrics["status"] = "error"
                self.metrics["running"] = False
                self.metrics["finished_at"] = time.time()

    def _run_events(self, events: Iterable[Any], speed: float, source_mode: str) -> None:
        detector = WindowedDetector(DetectionConfig(), scorer=self.scorer)
        started = time.perf_counter()
        last_event_time = None
        threat_counts: Counter[str] = Counter()

        def handle_event(event: Any) -> list[Alert]:
            nonlocal last_event_time
            if self._stop.is_set():
                return []
            if last_event_time is not None:
                source_gap = max(0.0, (event.timestamp - last_event_time).total_seconds())
                if source_mode != "live" and source_gap > 0:
                    time.sleep(source_gap / speed)
            last_event_time = event.timestamp
            processing_started = time.perf_counter()
            alerts = detector.process(event)
            processing_latency_ms = (time.perf_counter() - processing_started) * 1000
            with self._lock:
                self.metrics["processed_events"] += 1
                processed = self.metrics["processed_events"]
                previous_average = self.metrics["average_alert_latency_ms"]
                self.metrics["average_alert_latency_ms"] = round(
                    ((previous_average * (processed - 1)) + processing_latency_ms) / processed,
                    3,
                )
            return alerts

        def handle_alert(alert: Alert) -> None:
            with self._lock:
                self.alerts.appendleft(alert)
                incident = self.incidents.add(alert, self.metrics["data_provenance"])
                self.metrics["alerts_generated"] += 1
                self.metrics["incidents_generated"] = len(self.incidents.list(500))
                threat_counts[alert.threat_class] += 1
                self.metrics["threat_counts"] = dict(threat_counts)
            try:
                self.appwrite_sink.persist(alert)
            except Exception as exc:
                with self._lock:
                    self.metrics["error_count"] += 1
                    self.metrics["last_error"] = f"Appwrite persistence failed: {exc}"
            self._broadcast({"type": "alert", "alert": alert.model_dump(mode="json")})
            self._broadcast({"type": "incident", "incident": incident.model_dump(mode="json")})
            self._enqueue_explanation(alert)

        try:
            replay(events, handle_event, handle_alert)
            status = "stopped" if self._stop.is_set() else "completed"
        except Exception as exc:  # Keep the demo status visible instead of killing the API.
            with self._lock:
                self.metrics["error_count"] += 1
                self.metrics["last_error"] = str(exc)
            status = "error"
        with self._lock:
            elapsed = max(time.perf_counter() - started, 0.001)
            self.metrics["events_per_second"] = round(self.metrics["processed_events"] / elapsed, 2)
            self.metrics["status"] = status
            self.metrics["running"] = False
            self.metrics["finished_at"] = time.time()
            self.metrics["source_mode"] = source_mode
            self.metrics["data_provenance"] = (
                "authorized_live_metadata" if source_mode == "live" else "synthetic_fixture"
            )
        self._broadcast({"type": "metrics", "metrics": self.metrics})

    def _enqueue_explanation(self, alert: Alert) -> None:
        """Queue the alert for asynchronous explanation without blocking the replay."""
        for loop, _queue in list(self._subscribers):
            loop.call_soon_threadsafe(explanation_queue.put_nowait, alert)

    def _broadcast(self, message: dict[str, Any]) -> None:
        for loop, queue in list(self._subscribers):
            loop.call_soon_threadsafe(self._put_message, queue, message)

    @staticmethod
    def _put_message(queue: asyncio.Queue[dict[str, Any]], message: dict[str, Any]) -> None:
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
                queue.put_nowait(message)
            except asyncio.QueueEmpty:
                pass


explanation_queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=256)

manager = ReplayManager()


async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Probe Ollama on startup and stop the explanation worker on shutdown."""
    await startup()
    yield
    await shutdown()


app = FastAPI(title="SIH26145 Detection API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_origin_regex=r"https://[a-z0-9-]+-5173\.app\.github\.dev",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "read_only_replay"}


@app.get("/api/scenarios")
def scenarios() -> dict[str, list[str]]:
    return {"scenarios": manager.scenarios()}


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    return manager.metrics


@app.get("/api/alerts")
def alerts(limit: int = 100) -> dict[str, list[dict[str, Any]]]:
    bounded_limit = max(1, min(limit, 500))
    return {"alerts": [alert.model_dump(mode="json") for alert in list(manager.alerts)[:bounded_limit]]}


@app.get("/api/incidents")
def incidents(limit: int = 100) -> dict[str, list[dict[str, Any]]]:
    bounded_limit = max(1, min(limit, 500))
    return {"incidents": [incident.model_dump(mode="json") for incident in manager.incidents.list(bounded_limit)]}


@app.post("/api/replay/start")
def start_replay(request: ReplayRequest) -> dict[str, str]:
    try:
        manager.start(request.scenario, request.speed)
    except (RuntimeError, FileNotFoundError) as exc:
        raise HTTPException(status_code=409 if isinstance(exc, RuntimeError) else 404, detail=str(exc)) from exc
    return {"status": "started", "scenario": request.scenario}


@app.post("/api/replay/stop")
def stop_replay() -> dict[str, str]:
    manager.stop()
    return {"status": "stopped"}


@app.post("/api/live/start")
def start_live_capture(request: LiveCaptureRequest) -> dict[str, str]:
    try:
        manager.start_live(request.interface, request.bpf_filter)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "started", "source_mode": "live", "interface": request.interface or "default"}


@app.websocket("/ws/alerts")
async def alert_socket(websocket: WebSocket) -> None:
    await websocket.accept()
    subscription = manager.subscribe()
    try:
        await websocket.send_json({"type": "metrics", "metrics": manager.metrics})
        while True:
            message = await subscription[1].get()
            await websocket.send_json(message)
    except WebSocketDisconnect:
        pass
    finally:
        manager.unsubscribe(subscription)


@app.get("/api/explain/{alert_id}")
async def get_explanation(alert_id: str) -> dict[str, Any]:
    """Trigger and return an explanation for a single stored alert on demand."""
    alert = next((item for item in manager.alerts if item.alert_id == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.explanation:
        return {"alert_id": alert_id, "explanation": alert.explanation, "source": "cached"}
    result = await generate_explanation(alert)
    alert.explanation = result.explanation
    manager._broadcast(
        {
            "type": "explained",
            "alert_id": alert_id,
            "explanation": result.explanation,
            "source": result.source,
        }
    )
    return {"alert_id": alert_id, "explanation": result.explanation, "source": result.source}


explainer_task: asyncio.Task[None] | None = None


async def startup() -> None:
    """Probe Ollama and start the asynchronous explanation worker."""
    global explainer_task
    manager.ollama_status["available"] = await check_ollama()

    async def on_explained(alert_id: str, result: Any) -> None:
        explanation, source = result.explanation, result.source
        with manager._lock:
            for alert in manager.alerts:
                if alert.alert_id == alert_id:
                    alert.explanation = explanation
                    break
        manager._broadcast(
            {
                "type": "explained",
                "alert_id": alert_id,
                "explanation": explanation,
                "source": source,
            }
        )

    async def drain() -> None:
        while True:
            alert = await explanation_queue.get()
            result = await generate_explanation(alert)
            await on_explained(alert.alert_id, result)

    explainer_task = asyncio.create_task(drain())


async def shutdown() -> None:
    global explainer_task
    if explainer_task is not None:
        explainer_task.cancel()
        try:
            await explainer_task
        except asyncio.CancelledError:
            pass
        explainer_task = None


def run() -> None:
    import uvicorn

    uvicorn.run("sih_detector.api:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    run()
