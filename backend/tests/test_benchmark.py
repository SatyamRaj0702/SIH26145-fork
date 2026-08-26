from sih_detector.benchmark import generate_stream, run_benchmark


def test_benchmark_reports_positive_throughput_and_latency() -> None:
    stream = generate_stream(count=100, seed=3)
    assert len(stream) == 100

    # Use the default model directory (when present) so ML scoring is exercised.
    result = run_benchmark(event_count=150, declared_rate=50, warmup=20, seed=3, model_dir=None)
    assert result["sustained_events_per_second"] > 0
    latency = result["latency_ms"]
    assert latency["p50"] >= 0
    assert latency["p95"] >= latency["p50"]
    assert latency["p99"] >= latency["p95"]
    assert result["declared_rate_events_per_second"] == 50
