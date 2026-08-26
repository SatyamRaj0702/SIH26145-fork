# Problem interpretation and scope

## Problem statement

**SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic** is a software problem statement from the National Technical Research Organisation (NTRO).

The target environment is a monitoring enclave receiving a one-way copy of traffic from a gateway or peering link. The enclave can observe traffic but has no physical or protocol-level path back to the production network.

## Product definition

We are building a **passive cyber-threat intelligence application** consisting of:

1. A Python streaming detection engine.
2. An application backend for persistence, authentication, and realtime delivery.
3. A React web dashboard for investigation and demonstration.
4. A reproducible synthetic-traffic replay environment.

This is software with a web dashboard, not a static website and not an inline firewall.

## Inputs

The first prototype consumes replayable JSONL flow events. The design leaves room for PCAP-derived events and NetFlow/IPFIX/sFlow adapters later.

Each event contains only passively observed metadata, such as:

- Timestamp and flow identifier
- Source/destination addresses and ports
- Protocol and packet/byte counts
- TCP flags and connection outcome
- DNS metadata
- TLS/QUIC metadata where available

## Outputs

The system emits structured alerts containing:

- Alert timestamp
- Flow or behavior identifier
- Threat class
- Severity
- Confidence score
- Supporting evidence features
- Model/rule version

Alerts are stored and shown in the dashboard in near real time.

## Threat classes

- Volumetric/protocol DDoS: SYN floods, UDP floods, reflection/amplification, spoofed-source patterns.
- Botnet C2 beaconing: periodic flows to a small set of destinations.
- DGA domains and DNS tunnelling: entropy, n-gram, length, and record-type anomalies.
- Malware in encrypted sessions: TLS/QUIC metadata only, including fingerprints and packet timing/size behavior.
- Reconnaissance and port scanning: source fan-out over hosts and ports.
- Data exfiltration: unusual outbound volume and asymmetric flow ratios.

## Hard constraints

The detector must:

- Treat ingest as strictly read-only.
- Never send probes or complete handshakes with observed hosts.
- Never send a mitigation command across the ingest path.
- Never decrypt TLS/QUIC payloads.
- Process traffic incrementally rather than only after a complete batch.
- State and demonstrate a throughput target.
- Emit a standardized alert record.

## SIH-focused scope

### In scope

- Synthetic and lab-generated traffic scenarios.
- JSONL streaming/replay as the initial input adapter.
- Explainable rules and local classical ML.
- Six supported prototype scenarios: SYN flood, port scanning, DNS tunnelling/DGA, beaconing, encrypted-session metadata anomaly, and exfiltration.
- Appwrite persistence and realtime updates.
- React/HeroUI dashboard.
- Metrics for throughput, latency, and detection quality.
- Optional local LLM-generated explanations from sanitized alert data.

### Out of scope

- Monitoring the user's home or campus network.
- Real attacks against external systems.
- Automatic blocking or response.
- Payload decryption.
- Real malware execution.
- A claim of implementing a physical hardware data diode.
- Production-scale SIEM replacement.

## Success statement

The prototype succeeds when an evaluator can start a replay, observe incremental processing, see an explainable alert appear live, inspect its evidence, and verify that no response path is used.
