from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import uuid4

from .features import (
    dns_label_entropy,
    dns_query_length,
    incomplete_ratio,
    lexical_domain_score,
    outbound_ratio,
    periodicity_score,
    source_entropy,
    syn_ratio,
    tls_metadata_score,
    total_packets,
    unique_destination_hosts,
    unique_destination_ports,
    unique_dns_query_ratio,
)
from .model import MLResult, ThreatScorer, score_window
from .schemas import Alert, Evidence, FlowEvent, Severity, ThreatClass


@dataclass(frozen=True)
class DetectionConfig:
    window_seconds: int = 5
    syn_packets_per_second: float = 1000.0
    syn_ratio: float = 0.8
    incomplete_ratio: float = 0.8
    port_scan_unique_ports: int = 20
    port_scan_window_seconds: int = 10
    dns_window_seconds: int = 30
    dns_min_queries: int = 8
    dns_entropy_threshold: float = 3.5
    dns_query_length_threshold: int = 30
    dga_min_queries: int = 6
    dga_score_threshold: float = 0.68
    beacon_window_seconds: int = 30
    beacon_min_events: int = 5
    beacon_periodicity_threshold: float = 0.85
    encrypted_score_threshold: float = 0.7
    exfil_window_seconds: int = 30
    exfil_min_bytes: int = 100_000
    exfil_ratio_threshold: float = 10.0
    udp_amp_window_seconds: int = 10
    udp_amp_packets_per_second: float = 50.0
    udp_amp_min_sources: int = 4
    udp_amp_ports: tuple[int, ...] = (53, 123, 1900, 11211)
    slowloris_window_seconds: int = 30
    slowloris_min_connections: int = 8
    slowloris_max_bytes_per_connection: int = 2000
    slowloris_max_connections_per_second: float = 1.0
    alert_cooldown_seconds: int = 30


class WindowedDetector:
    """Detectors operate only on events already received through the read-only input."""

    def __init__(
        self,
        config: DetectionConfig | None = None,
        scorer: ThreatScorer | None = None,
    ) -> None:
        self.config = config or DetectionConfig()
        self.scorer = scorer
        self._events: list[FlowEvent] = []
        self._last_alert: dict[tuple[str, ThreatClass], datetime] = {}

    def process(self, event: FlowEvent) -> list[Alert]:
        self._events.append(event)
        max_window = max(
            self.config.port_scan_window_seconds,
            self.config.dns_window_seconds,
            self.config.beacon_window_seconds,
            self.config.exfil_window_seconds,
        )
        cutoff = event.timestamp - timedelta(seconds=max_window)
        self._events = [item for item in self._events if item.timestamp >= cutoff]

        ml_result = score_window(self.scorer, self._events)
        alerts: list[Alert] = []
        syn_events = [
            item
            for item in self._events
            if item.timestamp >= event.timestamp - timedelta(seconds=self.config.window_seconds)
        ]
        alerts.extend(self._detect_syn_flood(event, syn_events, ml_result))
        alerts.extend(self._detect_port_scan(event, self._events, ml_result))
        alerts.extend(self._detect_dns_tunnelling(event, self._events, ml_result))
        alerts.extend(self._detect_dga(event, self._events, ml_result))
        alerts.extend(self._detect_beaconing(event, self._events, ml_result))
        alerts.extend(self._detect_encrypted_session(event, ml_result))
        alerts.extend(self._detect_exfiltration(event, self._events, ml_result))
        alerts.extend(self._detect_udp_amplification(event, self._events, ml_result))
        alerts.extend(self._detect_slowloris(event, self._events, ml_result))
        return alerts

    def _detect_syn_flood(self, event: FlowEvent, events: list[FlowEvent], ml_result: MLResult) -> list[Alert]:
        packet_rate = total_packets(events) / max(self.config.window_seconds, 1)
        ratio = syn_ratio(events)
        incomplete = incomplete_ratio(events)
        triggered = (
            packet_rate >= self.config.syn_packets_per_second
            and ratio >= self.config.syn_ratio
            and incomplete >= self.config.incomplete_ratio
        )
        if not triggered or self._already_alerted(event, ThreatClass.DDOS):
            return []

        confidence = min(
            0.99,
            0.65 + 0.15 * min(packet_rate / self.config.syn_packets_per_second, 2) + 0.2 * ratio,
        )
        evidence = [
            Evidence(feature="packets_per_second", value=round(packet_rate, 2), reason="Packet rate exceeded the configured flood threshold"),
            Evidence(feature="syn_ratio", value=round(ratio, 3), reason="Most observed events contain SYN flags"),
            Evidence(feature="incomplete_ratio", value=round(incomplete, 3), reason="Most observed connections did not complete"),
            Evidence(feature="source_entropy", value=round(source_entropy(events), 3), reason="Source diversity was measured from passive flow metadata"),
        ]
        return [self._alert(event, ThreatClass.DDOS, Severity.CRITICAL, confidence, evidence, "syn_flood_v1", ml_result)]

    def _detect_dns_tunnelling(self, event: FlowEvent, events: list[FlowEvent], ml_result: MLResult) -> list[Alert]:
        dns_events = [
            item
            for item in events
            if item.source_ip == event.source_ip
            and item.dns_query
            and item.timestamp >= event.timestamp - timedelta(seconds=self.config.dns_window_seconds)
        ]
        if len(dns_events) < self.config.dns_min_queries:
            return []
        entropies = [dns_label_entropy(item.dns_query) for item in dns_events]
        lengths = [dns_query_length(item.dns_query) for item in dns_events]
        average_entropy = sum(entropies) / len(entropies)
        average_length = sum(lengths) / len(lengths)
        unique_ratio = unique_dns_query_ratio(dns_events)
        triggered = (
            average_entropy >= self.config.dns_entropy_threshold
            and average_length >= self.config.dns_query_length_threshold
            and unique_ratio >= 0.75
        )
        if not triggered or self._already_alerted(event, ThreatClass.DNS_TUNNELLING):
            return []
        confidence = min(
            0.99,
            0.65
            + 0.1 * min(average_entropy / 5, 1)
            + 0.1 * min(average_length / 60, 1)
            + 0.15 * unique_ratio,
        )
        evidence = [
            Evidence(feature="query_entropy", value=round(average_entropy, 3), reason="DNS labels have high character entropy"),
            Evidence(feature="average_query_length", value=round(average_length, 2), reason="Queries are unusually long"),
            Evidence(feature="unique_query_ratio", value=round(unique_ratio, 3), reason="Most observed queries are unique"),
        ]
        return [self._alert(event, ThreatClass.DNS_TUNNELLING, Severity.HIGH, confidence, evidence, "dns_tunnelling_v1", ml_result)]

    def _detect_dga(self, event: FlowEvent, events: list[FlowEvent], ml_result: MLResult) -> list[Alert]:
        dns_events = [
            item
            for item in events
            if item.source_ip == event.source_ip
            and item.dns_query
            and item.dns_record_type != "TXT"
            and item.timestamp >= event.timestamp - timedelta(seconds=self.config.dns_window_seconds)
        ]
        if len(dns_events) < self.config.dga_min_queries:
            return []
        scores = [lexical_domain_score(item.dns_query) for item in dns_events]
        average_score = sum(scores) / len(scores)
        unique_ratio = unique_dns_query_ratio(dns_events)
        if average_score < self.config.dga_score_threshold or unique_ratio < 0.8:
            return []
        if self._already_alerted(event, ThreatClass.DGA):
            return []
        confidence = min(0.97, 0.65 + 0.25 * average_score + 0.1 * unique_ratio)
        evidence = [
            Evidence(feature="dga_lexical_score", value=round(average_score, 3), reason="Domain labels show algorithmically generated lexical characteristics"),
            Evidence(feature="unique_query_ratio", value=round(unique_ratio, 3), reason="The source queried mostly unique domains"),
            Evidence(feature="dga_query_count", value=len(dns_events), reason="Repeated suspicious DNS queries were observed in a bounded window"),
        ]
        return [self._alert(event, ThreatClass.DGA, Severity.HIGH, confidence, evidence, "dga_v1", ml_result)]

    def _detect_beaconing(self, event: FlowEvent, events: list[FlowEvent], ml_result: MLResult) -> list[Alert]:
        beacon_events = [
            item
            for item in events
            if item.source_ip == event.source_ip
            and item.destination_ip == event.destination_ip
            and item.connection_completed is True
            and item.timestamp >= event.timestamp - timedelta(seconds=self.config.beacon_window_seconds)
        ]
        score = periodicity_score(beacon_events)
        if len(beacon_events) < self.config.beacon_min_events or score < self.config.beacon_periodicity_threshold:
            return []
        if self._already_alerted(event, ThreatClass.BOTNET_BEACONING):
            return []
        confidence = min(0.98, 0.7 + 0.25 * score)
        evidence = [
            Evidence(feature="periodicity_score", value=round(score, 3), reason="Flow arrivals occur at a regular interval"),
            Evidence(feature="recurring_destination", value=event.destination_ip, reason="The source repeatedly contacted the same destination"),
            Evidence(feature="beacon_event_count", value=len(beacon_events), reason="Repeated flow behavior was observed in a bounded window"),
        ]
        return [self._alert(event, ThreatClass.BOTNET_BEACONING, Severity.HIGH, confidence, evidence, "beaconing_v1", ml_result)]

    def _detect_encrypted_session(self, event: FlowEvent, ml_result: MLResult) -> list[Alert]:
        score = tls_metadata_score(event)
        if score < self.config.encrypted_score_threshold:
            return []
        if self._already_alerted(event, ThreatClass.ENCRYPTED_SESSION_ANOMALY):
            return []
        evidence = [
            Evidence(feature="tls_metadata_score", value=round(score, 3), reason="TLS/QUIC metadata matches an unusual encrypted-session pattern"),
            Evidence(feature="tls_fingerprint", value=event.tls_fingerprint or "unknown", reason="Fingerprint was evaluated without decrypting payload"),
            Evidence(feature="packet_size_signature", value=event.tls_packet_sizes, reason="Packet-size metadata was analyzed without payload access"),
        ]
        return [self._alert(event, ThreatClass.ENCRYPTED_SESSION_ANOMALY, Severity.MEDIUM, min(0.95, 0.6 + score * 0.35), evidence, "encrypted_metadata_v1", ml_result)]

    def _detect_exfiltration(self, event: FlowEvent, events: list[FlowEvent], ml_result: MLResult) -> list[Alert]:
        source_events = [
            item
            for item in events
            if item.source_ip == event.source_ip
            and item.timestamp >= event.timestamp - timedelta(seconds=self.config.exfil_window_seconds)
        ]
        bytes_sent = sum(item.bytes for item in source_events if item.direction == "outbound")
        ratio = outbound_ratio(source_events)
        if bytes_sent < self.config.exfil_min_bytes or ratio < self.config.exfil_ratio_threshold:
            return []
        if self._already_alerted(event, ThreatClass.DATA_EXFILTRATION):
            return []
        confidence = min(0.97, 0.65 + 0.2 * min(ratio / 25, 1) + 0.1 * min(bytes_sent / 1_000_000, 1))
        evidence = [
            Evidence(feature="outbound_bytes", value=bytes_sent, reason="Outbound volume exceeded the configured source-window threshold"),
            Evidence(feature="outbound_inbound_ratio", value=round(ratio, 3), reason="Outbound bytes were highly asymmetric against inbound bytes"),
            Evidence(feature="source_window_events", value=len(source_events), reason="The behavior was calculated from incremental flow metadata"),
        ]
        return [self._alert(event, ThreatClass.DATA_EXFILTRATION, Severity.HIGH, confidence, evidence, "exfiltration_v1", ml_result)]

    def _detect_udp_amplification(self, event: FlowEvent, events: list[FlowEvent], ml_result: MLResult) -> list[Alert]:
        """UDP reflection/amplification and spoofed-source floods."""
        amp_events = [
            item
            for item in events
            if item.protocol.upper() == "UDP"
            and item.destination_port in self.config.udp_amp_ports
            and item.timestamp >= event.timestamp - timedelta(seconds=self.config.udp_amp_window_seconds)
        ]
        if not amp_events:
            return []
        packet_rate = total_packets(amp_events) / max(self.config.udp_amp_window_seconds, 1)
        sources = len({item.source_ip for item in amp_events})
        triggered = (
            packet_rate >= self.config.udp_amp_packets_per_second
            and sources >= self.config.udp_amp_min_sources
        )
        if not triggered or self._already_alerted(event, ThreatClass.UDP_AMPLIFICATION):
            return []
        confidence = min(
            0.98,
            0.65 + 0.2 * min(packet_rate / max(self.config.udp_amp_packets_per_second, 1), 1.5) + 0.15 * min(sources / 10, 1),
        )
        evidence = [
            Evidence(feature="udp_packets_per_second", value=round(packet_rate, 2), reason="UDP rate to amplification-prone ports exceeded the configured threshold"),
            Evidence(feature="distinct_sources", value=sources, reason="Many distinct source IPs indicate spoofed or reflected traffic"),
            Evidence(feature="amplification_ports", value=list(dict.fromkeys(item.destination_port for item in amp_events)), reason="Traffic targeted DNS/NTP/SSDP/memcached amplification ports"),
        ]
        return [self._alert(event, ThreatClass.UDP_AMPLIFICATION, Severity.HIGH, confidence, evidence, "udp_amplification_v1", ml_result)]

    def _detect_slowloris(self, event: FlowEvent, events: list[FlowEvent], ml_result: MLResult) -> list[Alert]:
        """Slow HTTP exhaustion: many held-open, incomplete connections."""
        slow_events = [
            item
            for item in events
            if item.protocol.upper() == "TCP"
            and item.destination_port in (80, 443, 8080)
            and item.connection_completed is False
            and item.timestamp >= event.timestamp - timedelta(seconds=self.config.slowloris_window_seconds)
        ]
        if len(slow_events) < self.config.slowloris_min_connections:
            return []
        average_bytes = sum(item.bytes for item in slow_events) / len(slow_events)
        span_seconds = max(
            (max(item.timestamp for item in slow_events) - min(item.timestamp for item in slow_events)).total_seconds(),
            0.5,
        )
        connection_rate = len(slow_events) / span_seconds
        if average_bytes > self.config.slowloris_max_bytes_per_connection:
            return []
        # Slowloris exhausts servers by holding connections open slowly; a high
        # arrival rate is a flood, not a slow-exhaustion pattern.
        if connection_rate > self.config.slowloris_max_connections_per_second:
            return []
        if self._already_alerted(event, ThreatClass.SLOWLORIS):
            return []
        confidence = min(0.97, 0.65 + 0.2 * min(len(slow_events) / 15, 1) + 0.15 * (1 - min(average_bytes / self.config.slowloris_max_bytes_per_connection, 1)))
        evidence = [
            Evidence(feature="held_open_connections", value=len(slow_events), reason="Many connections were initiated but never completed in the observation window"),
            Evidence(feature="average_bytes_per_connection", value=round(average_bytes, 1), reason="Connections carried very little data, consistent with slow exhaustion"),
            Evidence(feature="connection_rate_per_second", value=round(connection_rate, 3), reason="Connections accumulated at a low rate, consistent with slow exhaustion rather than a flood"),
            Evidence(feature="http_ports", value=[80, 443, 8080], reason="Connections targeted HTTP/HTTPS service ports"),
        ]
        return [self._alert(event, ThreatClass.SLOWLORIS, Severity.MEDIUM, confidence, evidence, "slowloris_v1", ml_result)]

    def _detect_port_scan(self, event: FlowEvent, events: list[FlowEvent], ml_result: MLResult) -> list[Alert]:
        source_events = [item for item in events if item.source_ip == event.source_ip]
        destination_ports = unique_destination_ports(source_events)
        destination_hosts = unique_destination_hosts(source_events)
        if destination_ports < self.config.port_scan_unique_ports or self._already_alerted(event, ThreatClass.PORT_SCANNING):
            return []

        confidence = min(0.99, 0.7 + 0.02 * min(destination_ports - self.config.port_scan_unique_ports, 10))
        evidence = [
            Evidence(feature="unique_destination_ports", value=destination_ports, reason="One source contacted many destination ports in the observation window"),
            Evidence(feature="unique_destination_hosts", value=destination_hosts, reason="Destination fan-out was calculated without active probing"),
        ]
        return [self._alert(event, ThreatClass.PORT_SCANNING, Severity.HIGH, confidence, evidence, "port_scan_v1", ml_result)]

    def _already_alerted(self, event: FlowEvent, threat_class: ThreatClass) -> bool:
        key = (event.source_ip, threat_class)
        previous = self._last_alert.get(key)
        return previous is not None and event.timestamp - previous < timedelta(seconds=self.config.alert_cooldown_seconds)

    def _alert(
        self,
        event: FlowEvent,
        threat_class: ThreatClass,
        severity: Severity,
        confidence: float,
        evidence: list[Evidence],
        detector: str,
        ml_result: MLResult | None = None,
    ) -> Alert:
        self._last_alert[(event.source_ip, threat_class)] = event.timestamp
        model_version = "rules-v1"
        if ml_result is not None and ml_result.available:
            model_version = f"rules+{ml_result.model_version}"
            evidence = [
                *evidence,
                Evidence(
                    feature="ml_prediction",
                    value=ml_result.predicted_class,
                    reason=(
                        "Local model prediction supports the rule finding"
                        if ml_result.threat_class == threat_class
                        else "Local model prediction; rule evidence remains authoritative"
                    ),
                ),
                Evidence(feature="ml_anomaly_score", value=ml_result.anomaly_score, reason="Local anomaly score from passive window features"),
            ]
            if ml_result.threat_class == threat_class:
                confidence = min(0.99, confidence * 0.6 + ml_result.confidence * 0.4)
        return Alert(
            alert_id=f"alert_{uuid4().hex}",
            timestamp=event.timestamp,
            flow_id=event.flow_id,
            threat_class=threat_class,
            severity=severity,
            confidence=round(confidence, 3),
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            protocol=event.protocol,
            window_seconds=max(self.config.port_scan_window_seconds, self.config.exfil_window_seconds),
            evidence=evidence,
            detector=detector,
            model_version=model_version,
        )
