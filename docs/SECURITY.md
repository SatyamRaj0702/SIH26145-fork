# Security constraints

## Passive-only operation

The detection engine must accept observed data but never communicate with the observed sources or destinations. There must be no probe, handshake completion, response packet, mitigation command, or inline blocking feature.

## No decryption

TLS and QUIC analysis uses metadata only, such as version, fingerprint, packet sizes, directions, timing, and flow behavior. Payloads are not decrypted or stored.

## Safe test traffic

Use fixture generation and isolated lab tools only. Do not target public hosts, campus infrastructure, production systems, or devices without authorization. Do not execute real malware.

## Application isolation

Appwrite, FastAPI, the dashboard, and the optional Ollama service belong to the application/control plane. They must not have a route into the simulated observed network. For the demo, keep all traffic sources local and controlled.

## Data minimization

Store derived metadata and alert evidence rather than raw payloads. Keep secrets in environment variables. Do not commit Appwrite credentials, model secrets, or private datasets.

## LLM boundary

The optional local LLM receives sanitized structured alerts only. It cannot change alert class, severity, confidence, or detector state. Generated text is advisory and must be labeled as an explanation.

## Authentication and authorization

Use Appwrite authentication and collection permissions. Dashboard users should only access the data intended for their project/demo environment.

## Auditability

Record detector version, model version, replay scenario, timestamps, and benchmark settings so each result can be reproduced and explained.
