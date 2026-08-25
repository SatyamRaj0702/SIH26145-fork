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

## Model plan

Start with scikit-learn models on normalized window-level features:

- Isolation Forest for unsupervised anomaly scoring.
- Random Forest or Gradient Boosting for labeled threat classification.
- StandardScaler or robust scaling where appropriate.

Models are trained locally on synthetic/lab-generated fixtures and saved as versioned artifacts. Evaluation must use scenario-separated data to reduce leakage between train and test sets.

## Confidence and severity

Confidence is a calibrated or documented score combining detector evidence and model output. It must not be presented as a probability unless calibration is verified.

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
