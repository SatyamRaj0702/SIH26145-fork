from __future__ import annotations

import asyncio
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .appwrite import AppwriteAlertSink
from .detectors import DetectionConfig, WindowedDetector
from .model import load_scorer
from .replay import read_events, replay
from .schemas import Alert


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_FIXTURE_DIR = PROJECT_ROOT / "data" / "fixtures"
DEFAULT_MODEL_DIR = PROJECT_ROOT / "models"


class ReplayRequest(BaseModel):
    scenario: str = Field(min_length=1)
    speed: float = Field(default=1.0, gt=0)


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
        self.appwrite_sink = AppwriteAlertSink()
        self.reset_metrics()

    def reset_metrics(self) -> None:
        with self._lock:
            self.metrics: dict[str, Any] = {
                "processed_events": 0,
                "alerts_generated": 0,
                "events_per_second": 0.0,
                "average_alert_latency_ms": 0.0,
                "scenario": None,
                "status": "idle",
                "started_at": None,
                "finished_at": None,
                "threat_counts": {},
                "error_count": 0,
                "model_status": self.model_status,
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
        self.reset_metrics()
        self.metrics.update({"scenario": scenario, "status": "running", "started_at": time.time()})
        self._thread = threading.Thread(
            target=self._run,
            args=(path, speed),
            daemon=True,
            name="sih-replay",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        with self._lock:
            if self.metrics["status"] == "running":
                self.metrics["status"] = "stopped"
                self.metrics["finished_at"] = time.time()

    def subscribe(self) -> tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]:
        subscription = (asyncio.get_running_loop(), asyncio.Queue(maxsize=100))
        self._subscribers.add(subscription)
        return subscription

    def unsubscribe(self, subscription: tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]) -> None:
        self._subscribers.discard(subscription)

    def _run(self, path: Path, speed: float) -> None:
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
                if source_gap > 0:
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
                self.metrics["alerts_generated"] += 1
                threat_counts[alert.threat_class] += 1
                self.metrics["threat_counts"] = dict(threat_counts)
            try:
                self.appwrite_sink.persist(alert)
            except Exception as exc:
                with self._lock:
                    self.metrics["error_count"] += 1
                    self.metrics["last_error"] = f"Appwrite persistence failed: {exc}"
            self._broadcast({"type": "alert", "alert": alert.model_dump(mode="json")})

        try:
            replay(read_events(path), handle_event, handle_alert)
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
            self.metrics["finished_at"] = time.time()
        self._broadcast({"type": "metrics", "metrics": self.metrics})

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


manager = ReplayManager()
app = FastAPI(title="SIH26145 Detection API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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


def run() -> None:
    import uvicorn

    uvicorn.run("sih_detector.api:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    run()
