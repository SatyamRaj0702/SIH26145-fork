from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ThreatClass(StrEnum):
    DDOS = "ddos"
    BOTNET_BEACONING = "botnet_beaconing"
    DGA = "dga"
    DNS_TUNNELLING = "dns_tunnelling"
    ENCRYPTED_SESSION_ANOMALY = "encrypted_session_anomaly"
    PORT_SCANNING = "port_scanning"
    DATA_EXFILTRATION = "data_exfiltration"
    UDP_AMPLIFICATION = "udp_amplification"
    SLOWLORIS = "slowloris"
    UNKNOWN_ANOMALY = "unknown_anomaly"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FlowEvent(BaseModel):
    """A normalized passive observation; no response or payload fields are modeled."""

    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    flow_id: str = Field(min_length=1)
    source_ip: str = Field(min_length=1)
    destination_ip: str = Field(min_length=1)
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    protocol: str = Field(min_length=1)
    packets: int = Field(ge=0)
    bytes: int = Field(ge=0)
    direction: Literal["inbound", "outbound", "unknown"] = "unknown"
    tcp_flags: list[str] = Field(default_factory=list)
    connection_completed: bool | None = None
    dns_query: str | None = None
    dns_record_type: str | None = None
    tls_fingerprint: str | None = None
    tls_version: str | None = None
    tls_client_hello: bool = False
    tls_server_hello: bool = False
    quic_version: str | None = None
    tls_packet_sizes: list[int] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Evidence(BaseModel):
    feature: str = Field(min_length=1)
    value: Any
    reason: str = Field(min_length=1)


class Alert(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    alert_id: str = Field(min_length=1)
    timestamp: datetime
    flow_id: str = Field(min_length=1)
    threat_class: ThreatClass
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    source_ip: str = Field(min_length=1)
    destination_ip: str = Field(min_length=1)
    protocol: str = Field(min_length=1)
    window_seconds: int = Field(gt=0)
    evidence: list[Evidence] = Field(min_length=1)
    detector: str = Field(min_length=1)
    model_version: str = Field(min_length=1)
    explanation: str | None = None

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Incident(BaseModel):
    """A time-windowed group of alerts for the same threat destination."""

    incident_id: str = Field(min_length=1)
    threat_class: ThreatClass
    destination_ip: str = Field(min_length=1)
    protocol: str = Field(min_length=1)
    started_at: datetime
    last_seen_at: datetime
    window_seconds: int = Field(gt=0)
    alert_count: int = Field(ge=1)
    source_ips: list[str] = Field(min_length=1)
    max_confidence: float = Field(ge=0, le=1)
    severity: Severity
    alert_ids: list[str] = Field(min_length=1)
    provenance: Literal["synthetic_fixture", "authorized_live_metadata"]

    @field_validator("started_at", "last_seen_at")
    @classmethod
    def normalize_incident_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
