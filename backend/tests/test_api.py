from pathlib import Path

from fastapi.testclient import TestClient

from sih_detector.api import ReplayManager, app


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "mode": "read_only_replay"}


def test_scenario_endpoint_lists_jsonl_fixtures() -> None:
    client = TestClient(app)
    scenarios = client.get("/api/scenarios").json()["scenarios"]
    assert {"syn_flood", "dns_tunnelling", "beaconing"}.issubset(scenarios)


def test_metrics_declares_data_provenance() -> None:
    client = TestClient(app)
    metrics = client.get("/api/metrics").json()
    assert metrics["data_provenance"] in {"none", "synthetic_fixture", "authorized_live_metadata"}


def test_unknown_scenario_is_rejected(tmp_path: Path) -> None:
    manager = ReplayManager(tmp_path)
    try:
        manager.start("missing", 1)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Unknown fixture should be rejected")
