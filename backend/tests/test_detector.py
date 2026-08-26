from datetime import datetime, timedelta, timezone

from sih_detector.detectors import DetectionConfig, WindowedDetector
from sih_detector.replay import replay
from sih_detector.schemas import FlowEvent, Severity, ThreatClass


BASE_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


def event(
    index: int,
    *,
    source_ip: str = "10.0.0.8",
    destination_port: int = 443,
    packets: int = 1,
    syn: bool = False,
    completed: bool | None = None,
    dns_query: str | None = None,
    dns_record_type: str | None = None,
    destination_ip: str = "10.0.0.10",
) -> FlowEvent:
    return FlowEvent(
        timestamp=BASE_TIME + timedelta(seconds=index / 100),
        flow_id=f"flow-{index}",
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=40000 + index,
        destination_port=destination_port,
        protocol="TCP",
        packets=packets,
        bytes=packets * 64,
        tcp_flags=["SYN"] if syn else [],
        connection_completed=completed,
        dns_query=dns_query,
        dns_record_type=dns_record_type,
    )


def test_naive_timestamp_is_normalized_to_utc() -> None:
    item = event(0)
    parsed = FlowEvent.model_validate({**item.model_dump(), "timestamp": "2026-08-25T12:00:00"})
    assert parsed.timestamp.tzinfo == timezone.utc


def test_syn_flood_alert_contains_explainable_evidence() -> None:
    detector = WindowedDetector(
        DetectionConfig(syn_packets_per_second=10, syn_ratio=0.8, incomplete_ratio=0.8)
    )

    alerts = []
    for index in range(20):
        alerts.extend(detector.process(event(index, packets=5, syn=True, completed=False)))

    assert len(alerts) == 1
    assert alerts[0].threat_class == ThreatClass.DDOS
    assert alerts[0].severity == Severity.CRITICAL
    assert {item.feature for item in alerts[0].evidence} >= {
        "packets_per_second",
        "syn_ratio",
        "incomplete_ratio",
    }


def test_port_scan_alerts_once_per_window() -> None:
    detector = WindowedDetector(DetectionConfig(port_scan_unique_ports=3))

    alerts = []
    for index in range(5):
        alerts.extend(detector.process(event(index, destination_port=8000 + index)))

    assert len(alerts) == 1
    assert alerts[0].threat_class == ThreatClass.PORT_SCANNING
    assert alerts[0].severity == Severity.HIGH


def test_dns_tunnelling_alert_uses_metadata_only() -> None:
    detector = WindowedDetector(
        DetectionConfig(dns_min_queries=4, dns_entropy_threshold=3.0, dns_query_length_threshold=20)
    )
    query_base = "a8f3k2m9q1w7x4z6b8n0p3r5t7y9c2d1"

    alerts = []
    for index in range(4):
        alerts.extend(
            detector.process(
                event(
                    index * 2,
                    source_ip="10.0.0.21",
                    destination_port=53,
                    dns_query=f"{query_base}{index}.example.test",
                    dns_record_type="TXT",
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].threat_class == ThreatClass.DNS_TUNNELLING
    assert alerts[0].severity == Severity.HIGH
    assert {item.feature for item in alerts[0].evidence} >= {
        "query_entropy",
        "average_query_length",
        "unique_query_ratio",
    }


def test_beaconing_alert_uses_periodic_arrivals() -> None:
    detector = WindowedDetector(DetectionConfig(beacon_min_events=5, beacon_periodicity_threshold=0.8))

    alerts = []
    for index in range(6):
        alerts.extend(
            detector.process(
                event(
                    index * 500,
                    source_ip="10.0.0.31",
                    destination_ip="203.0.113.44",
                    destination_port=443,
                    completed=True,
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].threat_class == ThreatClass.BOTNET_BEACONING
    assert alerts[0].severity == Severity.HIGH
    assert any(item.feature == "periodicity_score" for item in alerts[0].evidence)


def test_replay_processes_events_incrementally() -> None:
    detector = WindowedDetector(DetectionConfig(port_scan_unique_ports=2))
    received = []
    events = [event(0, destination_port=80), event(1, destination_port=81)]

    processed = replay(events, detector.process, on_alert=received.append)

    assert processed == 2
    assert len(received) == 1
