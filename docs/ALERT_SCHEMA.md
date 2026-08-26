# Alert schema

Alerts are structured records intended for storage, realtime delivery, replay, and evaluation.

## Required fields

```json
{
  "timestamp": "2026-08-25T12:30:15.245Z",
  "flow_id": "10.0.0.4:53144-10.0.0.53:53",
  "threat_class": "dns_tunnelling",
  "confidence": 0.94,
  "evidence": [
    {
      "feature": "query_entropy",
      "value": 4.82,
      "reason": "DNS label entropy is above the learned baseline"
    }
  ]
}
```

## Recommended full record

```json
{
  "alert_id": "alert_01J...",
  "timestamp": "2026-08-25T12:30:15.245Z",
  "flow_id": "10.0.0.4:53144-10.0.0.53:53",
  "threat_class": "dns_tunnelling",
  "severity": "high",
  "confidence": 0.94,
  "source": {
    "ip": "10.0.0.4",
    "port": 53144
  },
  "destination": {
    "ip": "10.0.0.53",
    "port": 53
  },
  "protocol": "UDP",
  "window_seconds": 30,
  "evidence": [
    {
      "feature": "query_entropy",
      "value": 4.82,
      "reason": "DNS label entropy is above the learned baseline"
    },
    {
      "feature": "average_query_length",
      "value": 47,
      "reason": "Queries are unusually long"
    }
  ],
  "detector": "dns_tunnelling_v1",
  "model_version": "hybrid-v1",
  "explanation": null
}
```

## Enumerations

`threat_class` values:

```text
ddos
udp_amplification
slowloris
botnet_beaconing
dga
dns_tunnelling
encrypted_session_anomaly
port_scanning
data_exfiltration
unknown_anomaly
```

`severity` values:

```text
critical
high
medium
low
info
```

Confidence is a number from 0 to 1. It must be documented as a detector confidence score, not automatically as a statistically calibrated probability.

## Event contract

The normalized input event should contain a timestamp, flow identity, addresses/ports, protocol, packet/byte counts, and optional protocol metadata. The schema should support missing values because passive observation does not guarantee every field is available.

## Storage guidance

Persist alert fields needed for filtering as indexed fields. Store the evidence array and optional explanation as JSON. Raw PCAPs belong in Appwrite Storage or local fixture storage, not in the alert database.
