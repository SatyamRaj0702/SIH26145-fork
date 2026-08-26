from datetime import datetime, timedelta, timezone

from sih_detector.features import extract_window_features
from sih_detector.model import FEATURE_NAMES, features_to_vector, load_scorer
from sih_detector.schemas import FlowEvent, ThreatClass
from sih_detector.train import generate_dataset, train_and_save

BASE_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


def ddos_window() -> list[FlowEvent]:
    return [
        FlowEvent(
            timestamp=BASE_TIME + timedelta(seconds=index),
            flow_id=f"ml-{index}",
            source_ip=f"198.51.100.{index + 2}",
            destination_ip="10.0.0.10",
            source_port=40000 + index,
            destination_port=80,
            protocol="TCP",
            packets=20,
            bytes=64,
            tcp_flags=["SYN"],
            connection_completed=False,
        )
        for index in range(10)
    ]


def test_window_features_cover_all_model_fields() -> None:
    features = extract_window_features(ddos_window(), window_seconds=5.0)
    vector = features_to_vector(features)
    assert len(vector) == len(FEATURE_NAMES)
    assert all(isinstance(value, float) for value in vector)
    assert features.syn_ratio == 1.0
    assert features.unique_sources == 10
    assert features.periodicity_score == 1.0


def test_training_returns_usable_artifacts(tmp_path) -> None:
    result = train_and_save(output_dir=tmp_path, per_class=20, seed=7)
    assert result["accuracy"] >= 0.8
    assert (tmp_path / "threat_classifier.joblib").is_file()
    assert (tmp_path / "anomaly_detector.joblib").is_file()
    assert (tmp_path / "model_meta.json").is_file()

    scorer = load_scorer(tmp_path)
    assert scorer is not None
    ml_result = scorer.score(extract_window_features(ddos_window(), window_seconds=5.0))
    assert ml_result.available
    assert ml_result.threat_class == ThreatClass.DDOS
    assert ml_result.confidence >= 0.5


def test_training_reports_per_class_metrics_on_separated_scenarios(tmp_path) -> None:
    result = train_and_save(output_dir=tmp_path, per_class=15, seed=11, eval_seed=12, eval_per_class=10)
    metrics = result["per_class_metrics"]
    assert set(metrics) == set(
        [
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
    )
    for label, values in metrics.items():
        assert 0 <= values["precision"] <= 1
        assert 0 <= values["recall"] <= 1
        assert 0 <= values["f1"] <= 1
    assert result["eval_seed"] == 12
    assert result["evaluated_on"] == 10 * 10
    # Scenario-separated accuracy on separable synthetic classes stays strong.
    assert result["accuracy"] >= 0.8


def test_generated_dataset_has_all_classes() -> None:
    vectors, labels = generate_dataset(per_class=10, seed=3)
    assert len(vectors) == len(labels) == 100
    assert set(labels) == {
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
    }
