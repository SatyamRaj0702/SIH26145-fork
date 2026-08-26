# Dataset and SIH demo

## Dataset policy

The demo uses synthetic and lab-generated traffic. Do not run attacks against external systems or use real malware. Attack labels are retained separately for evaluation and are not passed to the detector.

## Scenarios

### Benign baseline

Include normal DNS, HTTP/HTTPS-like flows, SSH-like sessions, routine service traffic, and varied but non-malicious rates.

### SYN flood

Generate a high-rate collection of SYN-heavy flows with low completion behavior and diverse/spoofed-looking source addresses in the fixture data.

Expected evidence:

- SYN rate far above baseline.
- Low completion ratio.
- High source diversity.

### DNS tunnelling

Generate long, high-entropy labels with a high unique-label ratio and unusual query frequency/record types.

Expected evidence:

- High label entropy.
- Long queries.
- Repeated unique subdomains.

### Botnet beaconing

Generate repeated flows from a source to a rare destination with a stable interval and packet-size pattern.

Expected evidence:

- Low inter-arrival variation.
- Recurring destination.
- Periodicity above baseline.

### Additional scenarios

The prototype also includes port scanning, DGA, encrypted-session metadata anomalies, exfiltration, UDP amplification, and Slowloris fixtures, so every threat category in the problem statement has a replayable demo scenario.

## Replay behavior

The replay engine emits events incrementally at a configurable speed and records:

- Events emitted.
- Events processed.
- Alerts generated.
- Replay duration.
- Throughput.
- Alert latency.
- Errors and dropped events.

The same fixture and speed should produce repeatable results.

## Demo script

1. Start local application services.
2. Open the dashboard and show healthy status.
3. Select the SYN flood scenario.
4. Start replay.
5. Show processing rate and event count increasing.
6. Show the critical alert arriving live.
7. Open its evidence and confidence details.
8. Show the read-only architecture and no-response-path statement.
9. Repeat with DNS tunnelling, beaconing, DGA, encrypted-session metadata, or exfiltration.
10. End with benchmark metrics and limitations.

## Evaluation metrics

Report at minimum:

- Sustained events/flows per second.
- p50 and p95 alert latency.
- Precision, recall, and F1 by scenario where labels are available.
- False-positive count on benign replay.
- CPU and memory usage.
- Number of dropped or invalid events.

Initial target to validate, not assume:

```text
10,000 flow events/second
p95 alert latency under 2 seconds
```

The final README and presentation must contain measured values from the actual test environment.
