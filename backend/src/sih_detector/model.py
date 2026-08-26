"""Optional local scikit-learn models for threat classification and anomaly scoring.

The models are a complement to the deterministic rule detectors, never a
replacement. They are loaded lazily from ``models/``; when no artifact exists,
the pipeline runs in rules-only mode. All inference stays on-device and no
traffic leaves the enclave.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .features import WindowFeatures, extract_window_features
from .schemas import FlowEvent, ThreatClass

DEFAULT_MODEL_DIR = Path(__file__).resolve().parents[3] / "models"

FEATURE_NAMES = [
    "event_count",
    "packets_per_second",
    "bytes_per_second",
    "syn_ratio",
    "incomplete_ratio",
    "source_entropy",
    "unique_sources",
    "unique_destination_ports",
    "unique_destination_hosts",
    "dns_avg_entropy",
    "dns_avg_query_length",
    "dns_unique_query_ratio",
    "periodicity_score",
    "outbound_ratio",
    "tls_metadata_score",
]

CLASS_LABELS = [
    "benign",
    "ddos",
    "port_scanning",
    "dns_tunnelling",
    "dga",
    "botnet_beaconing",
    "encrypted_session_anomaly",
    "data_exfiltration",
    "udp_amplification",
    "slowloris",
]

LABEL_TO_THREAT = {
    "ddos": ThreatClass.DDOS,
    "port_scanning": ThreatClass.PORT_SCANNING,
    "dns_tunnelling": ThreatClass.DNS_TUNNELLING,
    "dga": ThreatClass.DGA,
    "botnet_beaconing": ThreatClass.BOTNET_BEACONING,
    "encrypted_session_anomaly": ThreatClass.ENCRYPTED_SESSION_ANOMALY,
    "data_exfiltration": ThreatClass.DATA_EXFILTRATION,
}


def features_to_vector(features: WindowFeatures) -> list[float]:
    """Return the feature values in the exact order the models were trained on."""
    data = features.model_dump()
    return [float(data[name]) for name in FEATURE_NAMES]


@dataclass(frozen=True)
class MLResult:
    """Output of the optional model layer for one event window."""

    available: bool
    predicted_class: str
    threat_class: ThreatClass | None
    probability: float
    anomaly_score: float
    confidence: float
    model_version: str


@dataclass(frozen=True)
class ThreatScorer:
    """Wraps the trained classifier and anomaly detector."""

    classifier: object
    anomaly_detector: object
    class_labels: list[str]
    version: str

    def score(self, features: WindowFeatures) -> MLResult:
        vector = [features_to_vector(features)]
        if self.classifier is not None:
            probabilities = self.classifier.predict_proba(vector)[0]
            prediction = str(self.classifier.predict(vector)[0])
            benign_index = list(self.class_labels).index("benign")
            probability = float(probabilities[benign_index])
            threat = LABEL_TO_THREAT.get(prediction)
        else:
            prediction = "benign"
            probability = 0.5
            threat = None
        anomaly_score = (
            float(self.anomaly_detector.decision_function(vector)[0])
            if self.anomaly_detector is not None
            else 0.0
        )
        # The anomaly detector is trained on benign windows only, so its signed
        # score is the most informative single confidence signal. Normalize it
        # to 0..1 and blend with the classifier probability when available.
        normalized_anomaly = max(0.0, min(1.0, (anomaly_score + 0.5) / 1.0))
        non_benign_confidence = 1.0 - probability
        if threat is None:
            confidence = normalized_anomaly
        else:
            confidence = 0.65 * non_benign_confidence + 0.35 * normalized_anomaly
        return MLResult(
            available=True,
            predicted_class=prediction,
            threat_class=threat,
            probability=round(probability, 3),
            anomaly_score=round(anomaly_score, 3),
            confidence=round(max(0.0, min(1.0, confidence)), 3),
            model_version=self.version,
        )


def score_window(scorer: ThreatScorer | None, events: list[FlowEvent]) -> MLResult:
    """Score a window through the model layer, or report an unavailable result."""
    if scorer is None or not events:
        return MLResult(
            available=False,
            predicted_class="unknown",
            threat_class=None,
            probability=0.0,
            anomaly_score=0.0,
            confidence=0.0,
            model_version="rules-only",
        )
    return scorer.score(extract_window_features(events))


def load_scorer(model_dir: str | Path = DEFAULT_MODEL_DIR) -> ThreatScorer | None:
    """Load the trained artifacts; return None when unavailable or incompatible."""
    model_dir = Path(model_dir)
    classifier_path = model_dir / "threat_classifier.joblib"
    anomaly_path = model_dir / "anomaly_detector.joblib"
    meta_path = model_dir / "model_meta.json"
    if not classifier_path.is_file() or not anomaly_path.is_file() or not meta_path.is_file():
        return None
    try:
        import joblib  # vendored by scikit-learn

        classifier = joblib.load(classifier_path)
        anomaly_detector = joblib.load(anomaly_path)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        version = str(meta.get("version", "ml-v1"))
        labels = list(meta.get("class_labels", CLASS_LABELS))
        return ThreatScorer(classifier=classifier, anomaly_detector=anomaly_detector, class_labels=labels, version=version)
    except Exception:
        return None
