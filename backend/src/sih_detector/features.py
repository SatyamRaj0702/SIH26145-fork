from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Sequence

from .schemas import FlowEvent


def source_entropy(events: Iterable[FlowEvent]) -> float:
    counts = Counter(event.source_ip for event in events)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def total_packets(events: Iterable[FlowEvent]) -> int:
    return sum(event.packets for event in events)


def total_bytes(events: Iterable[FlowEvent]) -> int:
    return sum(event.bytes for event in events)


def syn_ratio(events: Iterable[FlowEvent]) -> float:
    event_list = list(events)
    if not event_list:
        return 0.0
    syn_events = sum("SYN" in event.tcp_flags for event in event_list)
    return syn_events / len(event_list)


def incomplete_ratio(events: Iterable[FlowEvent]) -> float:
    values = [event.connection_completed for event in events if event.connection_completed is not None]
    if not values:
        return 0.0
    return sum(not completed for completed in values) / len(values)


def unique_destination_ports(events: Iterable[FlowEvent]) -> int:
    return len({event.destination_port for event in events})


def unique_destination_hosts(events: Iterable[FlowEvent]) -> int:
    return len({event.destination_ip for event in events})


def dns_label_entropy(query: str | None) -> float:
    if not query:
        return 0.0
    label = query.rstrip(".").split(".")[0].lower()
    if not label:
        return 0.0
    counts = Counter(label)
    length = len(label)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def dns_query_length(query: str | None) -> int:
    return len(query.rstrip(".")) if query else 0


def unique_dns_query_ratio(events: Iterable[FlowEvent]) -> float:
    queries = [event.dns_query for event in events if event.dns_query]
    if not queries:
        return 0.0
    return len(set(queries)) / len(queries)


def lexical_domain_score(query: str | None) -> float:
    """Heuristic DGA score using entropy, digit ratio, and uncommon consonant runs."""
    if not query:
        return 0.0
    label = query.rstrip(".").split(".")[0].lower()
    if not label:
        return 0.0
    entropy_score = min(dns_label_entropy(label) / 4.5, 1.0)
    digit_score = min(sum(character.isdigit() for character in label) / max(len(label) * 0.25, 1), 1.0)
    consonant_runs = sum(
        1 for left, right in zip(label, label[1:]) if left.isalpha() and right.isalpha() and left not in "aeiou" and right not in "aeiou"
    )
    run_score = min(consonant_runs / max(len(label) * 0.45, 1), 1.0)
    return round(0.55 * entropy_score + 0.25 * digit_score + 0.2 * run_score, 3)


def inter_arrival_seconds(events: Sequence[FlowEvent]) -> list[float]:
    ordered = sorted(events, key=lambda item: item.timestamp)
    return [
        (current.timestamp - previous.timestamp).total_seconds()
        for previous, current in zip(ordered, ordered[1:])
    ]


def periodicity_score(events: Sequence[FlowEvent]) -> float:
    intervals = [interval for interval in inter_arrival_seconds(events) if interval > 0]
    if len(intervals) < 2:
        return 0.0
    mean = sum(intervals) / len(intervals)
    deviation = sum(abs(interval - mean) for interval in intervals) / len(intervals)
    return max(0.0, 1.0 - (deviation / mean if mean else 1.0))


def outbound_ratio(events: Iterable[FlowEvent]) -> float:
    event_list = list(events)
    outbound = sum(event.bytes for event in event_list if event.direction == "outbound")
    inbound = sum(event.bytes for event in event_list if event.direction == "inbound")
    return outbound / max(inbound, 1)


def tls_metadata_score(event: FlowEvent) -> float:
    """Score unusual encrypted-session metadata; payloads are intentionally unavailable."""
    fingerprint_score = 0.35 if event.tls_fingerprint else 0.0
    version_score = 0.2 if event.tls_version in {"TLS1.0", "TLS1.1", "QUICv1-legacy"} else 0.0
    sizes = event.tls_packet_sizes
    burst_score = 0.45 if len(sizes) >= 4 and len(set(sizes)) <= 2 else 0.0
    return min(1.0, fingerprint_score + version_score + burst_score)
