from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from .schemas import Alert, Incident


class IncidentAggregator:
    """Merge alerts by threat, destination, protocol, and bounded time window."""

    def __init__(self, max_incidents: int = 500) -> None:
        self.max_incidents = max_incidents
        self._incidents: dict[tuple[str, str, str], Incident] = {}

    def clear(self) -> None:
        self._incidents.clear()

    def add(self, alert: Alert, provenance: str) -> Incident:
        key = (str(alert.threat_class), alert.destination_ip, alert.protocol.upper())
        current = self._incidents.get(key)
        allowed_gap = timedelta(seconds=max(1, alert.window_seconds))
        if current is None or alert.timestamp - current.last_seen_at > allowed_gap:
            current = Incident(
                incident_id=f"incident_{uuid4().hex}",
                threat_class=alert.threat_class,
                destination_ip=alert.destination_ip,
                protocol=alert.protocol.upper(),
                started_at=alert.timestamp,
                last_seen_at=alert.timestamp,
                window_seconds=alert.window_seconds,
                alert_count=1,
                source_ips=[alert.source_ip],
                max_confidence=alert.confidence,
                severity=alert.severity,
                alert_ids=[alert.alert_id],
                provenance=("authorized_live_metadata" if provenance == "authorized_live_metadata" else "synthetic_fixture"),
            )
            self._incidents[key] = current
            if len(self._incidents) > self.max_incidents:
                oldest_key = min(self._incidents, key=lambda item: self._incidents[item].last_seen_at)
                del self._incidents[oldest_key]
            return current
        sources = set(current.source_ips)
        sources.add(alert.source_ip)
        alert_ids = [*current.alert_ids, alert.alert_id]
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        severity = alert.severity if severity_rank[str(alert.severity)] >= severity_rank[str(current.severity)] else current.severity
        updated = current.model_copy(update={
            "last_seen_at": max(current.last_seen_at, alert.timestamp),
            "window_seconds": max(current.window_seconds, alert.window_seconds),
            "alert_count": current.alert_count + 1,
            "source_ips": sorted(sources),
            "max_confidence": max(current.max_confidence, alert.confidence),
            "severity": severity,
            "alert_ids": alert_ids,
        })
        self._incidents[key] = updated
        if len(self._incidents) > self.max_incidents:
            oldest_key = min(self._incidents, key=lambda item: self._incidents[item].last_seen_at)
            del self._incidents[oldest_key]
        return updated

    def list(self, limit: int = 100) -> list[Incident]:
        return sorted(self._incidents.values(), key=lambda item: item.last_seen_at, reverse=True)[:limit]