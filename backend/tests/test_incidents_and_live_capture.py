from datetime import datetime, timedelta, timezone

import pytest

from sih_detector.incidents import IncidentAggregator
from sih_detector.schemas import Alert, Evidence, Severity, ThreatClass


BASE_TIME = datetime(2026, 9, 11, 10, 0, tzinfo=timezone.utc)


def alert(index: int, **overrides: object) -> Alert:
    values: dict[str, object] = {
        "alert_id": f"alert-sanitized-{index}",
        "timestamp": BASE_TIME + timedelta(seconds=index),
        "flow_id": f"flow-{index}",
        "threat_class": ThreatClass.UDP_AMPLIFICATION,
        "severity": Severity.HIGH,
        "confidence": 0.91,
        "source_ip": f"198.51.100.{index + 1}",
        "destination_ip": "10.0.0.53",
        "protocol": "UDP",
        "window_seconds": 30,
        "evidence": [Evidence(feature="packet_rate", value=100, reason="sanitized fixture")],
        "detector": "udp_amplification_v1",
        "model_version": "rules-v1",
    }
    values.update(overrides)
    return Alert(**values)


def test_incident_groups_sources_within_window() -> None:
    aggregator = IncidentAggregator()
    first = aggregator.add(alert(0), "authorized_live_metadata")
    second = aggregator.add(alert(1), "authorized_live_metadata")

    assert first.incident_id == second.incident_id
    assert second.alert_count == 2
    assert second.source_ips == ["198.51.100.1", "198.51.100.2"]
    assert second.provenance == "authorized_live_metadata"


def test_incident_splits_after_window_or_key_change() -> None:
    aggregator = IncidentAggregator()
    first = aggregator.add(alert(0), "synthetic_fixture")
    later = aggregator.add(alert(31), "synthetic_fixture")
    other_destination = aggregator.add(alert(2, destination_ip="10.0.0.54"), "synthetic_fixture")

    assert later.incident_id != first.incident_id
    assert other_destination.incident_id != later.incident_id


def test_quic_parser_keeps_only_derived_metadata() -> None:
    scapy = pytest.importorskip("scapy.all")
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from sih_detector.live_capture import packet_to_event

    # Sanitized QUIC long-header packet: version 1, no application payload retained.
    packet = IP(src="192.0.2.10", dst="192.0.2.20") / UDP(sport=50000, dport=443) / Raw(
        load=b"\xc0\x00\x00\x00\x01"
    )
    event = packet_to_event(packet, {"192.0.2.10"})

    assert event is not None
    assert event.quic_version == "0x00000001"
    assert event.tls_packet_sizes == [len(packet)]
    assert not hasattr(event, "payload")


def test_tls_client_hello_derives_metadata_without_payload() -> None:
    pytest.importorskip("scapy.all")
    from scapy.layers.inet import IP, TCP
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.record import TLS
    from scapy.packet import Raw
    from sih_detector.live_capture import packet_to_event

    packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=50000, dport=443) / TLS() / TLSClientHello()
    # Raw bytes are sanitized fixture input and are not part of FlowEvent output.
    packet = packet / Raw(load=b"sanitized-handshake-marker")
    event = packet_to_event(packet, {"192.0.2.10"})

    assert event is not None
    assert event.tls_client_hello is True
    assert event.tls_fingerprint
    assert event.tls_packet_sizes == [len(packet)]
    assert not hasattr(event, "payload")