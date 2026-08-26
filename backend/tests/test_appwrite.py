from datetime import datetime, timezone

from sih_detector.appwrite import AppwriteAlertSink
from sih_detector.schemas import Alert, Evidence, Severity, ThreatClass


def sample_alert() -> Alert:
    return Alert(
        alert_id="alert-test-1",
        timestamp=datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc),
        flow_id="flow-test",
        threat_class=ThreatClass.DDOS,
        severity=Severity.CRITICAL,
        confidence=0.98,
        source_ip="198.51.100.10",
        destination_ip="10.0.0.10",
        protocol="TCP",
        window_seconds=5,
        evidence=[Evidence(feature="syn_ratio", value=1.0, reason="SYN ratio threshold exceeded")],
        detector="syn_flood_v1",
        model_version="rules-v1",
    )


def test_sink_is_disabled_without_environment(monkeypatch) -> None:
    monkeypatch.delenv("APPWRITE_ENDPOINT", raising=False)
    monkeypatch.delenv("APPWRITE_PROJECT_ID", raising=False)
    sink = AppwriteAlertSink()
    assert not sink.enabled
    assert sink.persist(sample_alert()) is False
    assert sink.status()["persisted_count"] == 0


def test_sink_persists_documents_and_tracks_count(monkeypatch) -> None:
    monkeypatch.setenv("APPWRITE_ENDPOINT", "https://cloud.appwrite.io/v1")
    monkeypatch.setenv("APPWRITE_PROJECT_ID", "project")
    monkeypatch.setenv("APPWRITE_DATABASE_ID", "db")
    monkeypatch.setenv("APPWRITE_ALERTS_COLLECTION_ID", "alerts")
    monkeypatch.setenv("APPWRITE_API_KEY", "secret")

    created: list[dict[str, object]] = []

    class FakeDatabases:
        def create_document(self, database_id, collection_id, document_id, data) -> None:
            created.append(
                {
                    "database_id": database_id,
                    "collection_id": collection_id,
                    "document_id": document_id,
                    "data": data,
                }
            )

    sink = AppwriteAlertSink()
    # Avoid an import-time dependency on the real SDK in this test environment.
    sink._databases = FakeDatabases()  # type: ignore[assignment]
    sink.enabled = True

    alert = sample_alert()
    assert sink.persist(alert) is True
    assert sink.persist(alert) is True
    assert sink.status()["persisted_count"] == 2
    assert created[0]["document_id"] == "alert-test-1"
    assert created[0]["data"]["threat_class"] == "ddos"
