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

- **Random Forest classifier** over the seven threat classes plus benign traffic.
- **Isolation Forest anomaly detector** trained on benign windows only.
- 15 window-level metadata features (rates, ratios, entropy, periodicity, byte asymmetry, TLS metadata).
- Artifacts saved as versioned files under `models/` (`threat_classifier.joblib`, `anomaly_detector.joblib`, `model_meta.json`).

Train the models with:

```bash
PYTHONPATH=backend/src python3 -m sih_detector.cli --train --per-class 250
```

When artifacts exist, each alert carries an `ml_prediction` and `ml_anomaly_score` evidence item and `model_version` becomes `rules+ml-v1`. When they do not, the pipeline runs rules-only and still emits every alert. Detection results always remain the responsibility of the rules; the model score only adjusts confidence when it agrees with the rule finding.

## Model plan (next)

- Scenario-separated evaluation to reduce leakage between train and test sets.
- Gradient Boosting comparison and calibration checks.
- Per-class precision/recall tracking as fixtures grow.

## Confidence and severity

Confidence is a documented score combining detector evidence and model output. When the local model agrees with the rule finding, confidence blends the rule score (60%) with the model score (40%), capped at 0.99. Confidence is not presented as a calibrated probability.

Severity is assigned from impact and confidence, with clear documented thresholds. Example initial policy:

- Critical: active volumetric behavior with high confidence.
- High: strong evidence of tunnelling, C2, scanning, or exfiltration.
- Medium: anomalous behavior requiring investigation.
- Low: weak or contextual anomaly.

## Explainability

Each alert includes the strongest contributing features and human-readable evidence. The dashboard must allow evaluators to inspect the evidence rather than seeing only a score.

## Optional small LLM

Qwen2.5-3B-Instruct through Ollama may generate a concise explanation from sanitized alert JSON. It runs asynchronously after the alert is emitted. If unavailable, a template renderer produces the explanation.

The LLM must never:

- Decide the threat class.
- Modify confidence or severity.
- Receive raw payloads or decrypted content.
- Send commands or contact network hosts.

## Training data policy

Use synthetic and lab-generated traffic only for the demo. Keep labels separate from inference input. Store dataset generation commands and scenario metadata so results are reproducible.
