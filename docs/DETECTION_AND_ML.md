# Detection and ML plan

## Hybrid principle

The system uses three layers:

1. **Rules** for recognizable, high-confidence behavior.
2. **Statistics** for rates, entropy, periodicity, and deviations from baseline.
3. **Local ML** for anomaly scoring and known-pattern classification.

The detector's structured result is authoritative. The optional LLM only explains that result.

## Threat features

### DDoS

- Packets/sec and bytes/sec.
- SYN-to-total packet ratio.
- Connection completion ratio when observable from passive metadata.
- Source-IP cardinality and entropy.
- Destination concentration.
- UDP amplification ratio.

### Beaconing

- Flow inter-arrival mean and standard deviation.
- Coefficient of variation.
- Periodicity score.
- Recurring destination count.
- Stable packet-size/burst pattern.

### DGA and DNS tunnelling

- Query and label length.
- Shannon entropy.
- Character n-gram rarity.
- Unique-label ratio.
- Query rate per source/domain.
- Record-type distribution, including unusual TXT use.

### Encrypted sessions

- TLS/QUIC version and metadata.
- JA3/JA3S or JA4 where available.
- Packet-size sequences.
- Directional burst timing.
- Session duration and recurrence.

No encrypted payload is decrypted.

### Reconnaissance

- Unique destination hosts and ports.
- Fan-out rate.
- Failed/sparse response ratio.
- Sequential or patterned port behavior.

### Exfiltration

- Outbound/inbound byte ratio.
- Total outbound volume.
- Destination rarity.
- Long-lived session behavior.
- Deviation from source baseline.

## Implemented rule baseline

The executable slice includes explainable rules for SYN floods, port scanning, DNS tunnelling, DGA-like domains, botnet beaconing, encrypted-session metadata anomalies, and data exfiltration. These rules provide the deterministic, authoritative baseline.

## Implemented local ML layer

A scikit-learn layer complements the rules. Training runs fully locally on synthetic windows and never touches payloads or the network:

- **Random Forest classifier** over the nine threat classes plus benign traffic.
- **Isolation Forest anomaly detector** trained on benign windows only.
- 15 window-level metadata features (rates, ratios, entropy, periodicity, byte asymmetry, TLS metadata).
- Artifacts saved as versioned files under `models/` (`threat_classifier.joblib`, `anomaly_detector.joblib`, `model_meta.json`).

Train the models with:

```bash
PYTHONPATH=backend/src python3 -m sih_detector.cli --train --per-class 250
```

When artifacts exist, each alert carries an `ml_prediction` and `ml_anomaly_score` evidence item and `model_version` becomes `rules+ml-v1`. When they do not, the pipeline runs rules-only and still emits every alert. Detection results always remain the responsibility of the rules; the model score only adjusts confidence when it agrees with the rule finding.

### Scenario-separated evaluation

Evaluation is **scenario-separated**: the evaluation set is generated with a different random seed (`--eval-seed`, default `seed + 1000`) than the training set, so the model is measured on windows it never saw. The train command reports per-class precision/recall/F1 and overall accuracy on this held-out scenario set.

Measured with `--per-class 250` (2,500 training + 2,500 evaluation windows):

| Class | Precision | Recall | F1 |
|---|---|---|---|
| benign | 1.00 | 1.00 | 1.00 |
| ddos | 1.00 | 1.00 | 1.00 |
| port_scanning | 1.00 | 1.00 | 1.00 |
| dns_tunnelling | 1.00 | 1.00 | 1.00 |
| dga | 1.00 | 1.00 | 1.00 |
| botnet_beaconing | 1.00 | 1.00 | 1.00 |
| encrypted_session_anomaly | 1.00 | 1.00 | 1.00 |
| data_exfiltration | 1.00 | 1.00 | 1.00 |
| udp_amplification | 1.00 | 1.00 | 1.00 |
| slowloris | 1.00 | 1.00 | 1.00 |

**Honest interpretation:** the synthetic generators are intentionally cleanly separable (e.g. benign DNS entropy ≈ 0.7 vs DGA ≈ 3.4 vs tunnelling ≈ 4.2), so perfect scores demonstrate the *pipeline* and the evaluation methodology, not real-world performance. The per-class framework is in place; meaningful precision/recall values require labeled real or lab-generated traffic (the training data policy above).

## Model plan (next)

- Scenario-separated evaluation to reduce leakage between train and test sets (implemented; see the measured table above).
- Gradient Boosting comparison and calibration checks.
- Per-class precision/recall tracking with real or lab-generated traffic as fixtures grow.

## Confidence and severity

Confidence is a documented score combining detector evidence and model output. When the local model agrees with the rule finding, confidence blends the rule score (60%) with the model score (40%), capped at 0.99. Confidence is not presented as a calibrated probability.

Severity is assigned from impact and confidence, with clear documented thresholds. Example initial policy:

- Critical: active volumetric behavior with high confidence.
- High: strong evidence of tunnelling, C2, scanning, or exfiltration.
- Medium: anomalous behavior requiring investigation.
- Low: weak or contextual anomaly.

## Explainability

Each alert includes the strongest contributing features and human-readable evidence. The dashboard must allow evaluators to inspect the evidence rather than seeing only a score.

## Implemented optional small LLM

Qwen2.5-3B-Instruct through Ollama generates a concise explanation from sanitized alert JSON. It runs asynchronously after the alert is emitted over the same WebSocket as `explained` messages; the alert and its score appear immediately, and the explanation streams into the dashboard drawer when ready.

Setup:

```bash
ollama pull qwen2.5:3b-instruct
# optional overrides: OLLAMA_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS
```

Behavior:

- On startup the API probes Ollama and reports `ollama_status` in `/api/metrics`; the dashboard shows an `Ollama` chip.
- The model receives only the sanitized alert (class, severity, confidence, hosts, protocol, evidence). No payloads or credentials.
- When Ollama is unreachable or times out, a deterministic template explanation is used; detection is never blocked.
- `GET /api/explain/{alert_id}` generates an explanation on demand.

The LLM must never:

- Decide the threat class.
- Modify confidence or severity.
- Receive raw payloads or decrypted content.
- Send commands or contact network hosts.

## Training data policy

Use synthetic and lab-generated traffic only for the demo. Keep labels separate from inference input. Store dataset generation commands and scenario metadata so results are reproducible.
