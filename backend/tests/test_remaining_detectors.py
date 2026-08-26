from datetime import datetime, timedelta, timezone

from sih_detector.detectors import DetectionConfig, WindowedDetector
from sih_detector.schemas import FlowEvent, Severity, ThreatClass


BASE_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


def event(index: int, **overrides: object) -> FlowEvent:
    values: dict[str, object] = {
        "timestamp": BASE_TIME + timedelta(seconds=index),
        "flow_id": f"remaining-{index}",
        "source_ip": "10.0.0.91",
        "destination_ip": "10.0.0.53",
        "source_port": 57000 + index,
        "destination_port": 53,
        "protocol": "UDP",
        "packets": 2,
        "bytes": 160,
        "dns_record_type": "A",
    }
    values.update(overrides)
    return FlowEvent(**values)


def test_dga_detector_uses_domain_metadata() -> None:
    detector = WindowedDetector(DetectionConfig(dga_min_queries=4, dga_score_threshold=0.45))
    alerts = []
    labels = ["x9q2m7v4k1z8p5r3", "n4t8c2w7j1h9y5p3", "q7b2m9x4v1k8z5r3", "p3s8d1f6g4h9j2k7"]
    for index, label in enumerate(labels):
        alerts.extend(detector.process(event(index, dns_query=f"{label}.example.test")))

    assert len(alerts) == 1
    assert alerts[0].threat_class == ThreatClass.DGA
    assert alerts[0].severity == Severity.HIGH


def test_encrypted_detector_never_requires_payload() -> None:
    detector = WindowedDetector(DetectionConfig(encrypted_score_threshold=0.7))
    alert = detector.process(
        event(
            0,
            destination_ip="203.0.113.77",
            destination_port=443,
            protocol="TCP",
            direction="outbound",
            connection_completed=True,
            tls_fingerprint="ja4-demo-rare",
            tls_version="TLS1.1",
            tls_packet_sizes=[64, 64, 128, 64, 64],
        )
    )

    assert len(alert) == 1
    assert alert[0].threat_class == ThreatClass.ENCRYPTED_SESSION_ANOMALY
    assert all("payload" not in item.feature.lower() for item in alert[0].evidence)


def test_udp_amplification_detector_uses_source_diversity() -> None:
    detector = WindowedDetector(
        DetectionConfig(udp_amp_packets_per_second=20, udp_amp_min_sources=1)
    )
    alerts = []
    for index in range(6):
        alerts.extend(
            detector.process(
                event(
                    index,
                    source_ip="198.51.100.2",
                    destination_ip="10.0.0.53",
                    destination_port=53,
                    protocol="UDP",
                    packets=50,
                    bytes=3000,
                )
            )
        )

    # One alert per distinct source (cooldown is keyed by source IP).
    assert len(alerts) == 1
    assert alerts[0].threat_class == ThreatClass.UDP_AMPLIFICATION
    assert alerts[0].severity == Severity.HIGH
    assert any(item.feature == "udp_packets_per_second" for item in alerts[0].evidence)


def test_slowloris_detector_uses_held_open_connections() -> None:
    detector = WindowedDetector(DetectionConfig(slowloris_min_connections=5))
    alerts = []
    for index in range(8):
        alerts.extend(
            detector.process(
                event(
                    index * 3,
                    destination_ip="10.0.0.10",
                    destination_port=80,
                    protocol="TCP",
                    packets=2,
                    bytes=128,
                    connection_completed=False,
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].threat_class == ThreatClass.SLOWLORIS
    assert alerts[0].severity == Severity.MEDIUM
    assert any(item.feature == "held_open_connections" for item in alerts[0].evidence)


def test_exfiltration_detector_uses_directional_bytes() -> None:
    detector = WindowedDetector(
        DetectionConfig(exfil_min_bytes=1000, exfil_ratio_threshold=10, exfil_window_seconds=30)
    )
    alerts = []
    for index in range(3):
        alerts.extend(
            detector.process(
                event(
                    index * 5,
                    destination_ip="203.0.113.88",
                    destination_port=443,
                    protocol="TCP",
                    direction="outbound",
                    bytes=1000,
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].threat_class == ThreatClass.DATA_EXFILTRATION
    assert alerts[0].severity == Severity.HIGH
