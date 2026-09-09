"""Import labeled flow CSV exports into the normalized training-window format.

The importer targets CICFlowMeter/CICIDS-style exports and stores metadata only.
It never reads or writes packet payloads.
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schemas import FlowEvent

LABEL_MAP = {
    "benign": "benign",
    "normal": "benign",
    "ddos": "ddos",
    "dos hulk": "ddos",
    "dos goldeneye": "ddos",
    "dos slowloris": "slowloris",
    "slowloris": "slowloris",
    "portscan": "port_scanning",
    "port scanning": "port_scanning",
    "bot": "botnet_beaconing",
    "botnet": "botnet_beaconing",
    "infiltration": "data_exfiltration",
    "data exfiltration": "data_exfiltration",
    "web attack": "dga",
    "dns tunneling": "dns_tunnelling",
    "dns tunnelling": "dns_tunnelling",
    "udp amplification": "udp_amplification",
}


def _key(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower().replace("_", " "))


def _columns(row: dict[str, str]) -> dict[str, str]:
    return {_key(name): value.strip() for name, value in row.items() if name}


def _value(row: dict[str, str], *names: str, default: str = "") -> str:
    for name in names:
        value = row.get(_key(name), "")
        if value != "":
            return value
    return default


def _number(value: str, default: float = 0.0) -> float:
    try:
        return float(value.replace(",", "").strip())
    except (AttributeError, ValueError):
        return default


def _timestamp(value: str, ordinal: int) -> datetime:
    for candidate in (value, value.replace("/", "-")):
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
        except ValueError:
            continue
    return datetime.fromtimestamp(ordinal, tz=timezone.utc)


def row_to_labeled_event(row: dict[str, str], ordinal: int) -> tuple[str, FlowEvent] | None:
    label_text = _key(_value(row, "Label", "Class", "Attack", default="benign"))
    label = LABEL_MAP.get(label_text)
    if label is None:
        return None
    source_ip = _value(row, "Src IP", "Source IP", "Source", default="0.0.0.0")
    destination_ip = _value(row, "Dst IP", "Destination IP", "Destination", default="0.0.0.0")
    source_port = int(_number(_value(row, "Src Port", "Source Port")))
    destination_port = int(_number(_value(row, "Dst Port", "Destination Port")))
    protocol_number = int(_number(_value(row, "Protocol")))
    protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol_number, _value(row, "Protocol", default="IP"))
    packets = int(_number(_value(row, "Tot Fwd Pkts", "Total Fwd Packets")))
    packets += int(_number(_value(row, "Tot Bwd Pkts", "Total Bwd Packets")))
    byte_count = int(_number(_value(row, "TotLen Fwd Pkts", "Total Length of Fwd Packets")))
    byte_count += int(_number(_value(row, "TotLen Bwd Pkts", "Total Length of Bwd Packets")))
    if packets <= 0:
        packets = 1
    if byte_count <= 0:
        byte_count = int(_number(_value(row, "Total Length of Fwd Packets", "Bytes"), 64))
    flags_text = _value(row, "Fwd Header Len", "TCP Flags", default="")
    tcp_flags = [name for marker, name in (("S", "SYN"), ("A", "ACK"), ("F", "FIN"), ("R", "RST")) if marker in flags_text.upper()]
    duration = _number(_value(row, "Flow Duration"))
    timestamp = _timestamp(_value(row, "Timestamp", "Date"), ordinal)
    event = FlowEvent(
        timestamp=timestamp,
        flow_id=f"csv_{ordinal}",
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=max(0, min(source_port, 65535)),
        destination_port=max(0, min(destination_port, 65535)),
        protocol=protocol,
        packets=packets,
        bytes=byte_count,
        direction="outbound",
        tcp_flags=tcp_flags,
        connection_completed=False if label in {"ddos", "slowloris"} else True,
    )
    return label, event


def import_labeled_flow_csv(
    input_path: str | Path,
    output_path: str | Path,
    window_size: int = 32,
    max_rows: int | None = None,
) -> dict[str, Any]:
    """Convert a labeled flow CSV into JSONL labeled windows."""
    windows: dict[str, list[FlowEvent]] = defaultdict(list)
    counts: dict[str, int] = defaultdict(int)
    skipped = 0
    with Path(input_path).open(encoding="utf-8-sig", errors="replace", newline="") as source:
        reader = csv.DictReader(source)
        for ordinal, raw_row in enumerate(reader):
            if max_rows is not None and ordinal >= max_rows:
                break
            result = row_to_labeled_event(_columns(raw_row), ordinal)
            if result is None:
                skipped += 1
                continue
            label, event = result
            windows[label].append(event)
            counts[label] += 1

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with output.open("w", encoding="utf-8") as target:
        for label, events in sorted(windows.items()):
            for start in range(0, len(events), window_size):
                chunk = events[start : start + window_size]
                if len(chunk) < max(2, window_size // 4):
                    continue
                target.write(json.dumps({"label": label, "events": [event.model_dump(mode="json") for event in chunk]}) + "\n")
                written += 1
    return {"input": str(input_path), "output": str(output), "rows_by_label": dict(counts), "windows": written, "skipped_unknown_labels": skipped}
