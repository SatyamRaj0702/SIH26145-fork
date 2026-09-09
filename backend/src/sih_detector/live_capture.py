"""Passive packet capture adapter for authorized local interfaces.

Only packet metadata is converted into FlowEvent objects. Payload bytes are
never stored or sent anywhere; the adapter is intentionally read-only.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from uuid import uuid4

from .schemas import FlowEvent


def _local_addresses() -> set[str]:
    """Return local addresses used to infer event direction."""
    import socket

    addresses = {"127.0.0.1", "::1"}
    hostname = socket.gethostname()
    for family, _kind, _proto, _canonname, sockaddr in socket.getaddrinfo(hostname, None):
        if family == socket.AF_INET:
            addresses.add(sockaddr[0])
        elif family == socket.AF_INET6:
            addresses.add(sockaddr[0].split("%", 1)[0])
    return addresses


def packet_to_event(packet: object, local_addresses: set[str] | None = None) -> FlowEvent | None:
    """Convert one Scapy IP packet into metadata-only normalized flow data."""
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if packet is None or not (packet.haslayer(IP) or packet.haslayer(IPv6)):
        return None

    network = packet[IP] if packet.haslayer(IP) else packet[IPv6]
    source_ip = str(network.src)
    destination_ip = str(network.dst)
    protocol = "ip"
    source_port = 0
    destination_port = 0
    tcp_flags: list[str] = []
    completed: bool | None = None

    if packet.haslayer(TCP):
        transport = packet[TCP]
        protocol = "TCP"
        source_port = int(transport.sport)
        destination_port = int(transport.dport)
        flags = str(transport.flags)
        flag_names = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH"}
        tcp_flags = [name for flag, name in flag_names.items() if flag in flags]
        if "F" in flags or "R" in flags:
            completed = True
        elif "S" in flags and "A" not in flags:
            completed = False
    elif packet.haslayer(UDP):
        transport = packet[UDP]
        protocol = "UDP"
        source_port = int(transport.sport)
        destination_port = int(transport.dport)

    dns_query = None
    dns_record_type = None
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        question = packet[DNSQR]
        raw_name = bytes(question.qname).rstrip(b".")
        dns_query = raw_name.decode("utf-8", errors="replace")
        record_types = {1: "A", 28: "AAAA", 5: "CNAME", 16: "TXT", 65: "HTTPS"}
        dns_record_type = record_types.get(int(question.qtype), str(question.qtype))

    addresses = local_addresses or set()
    if source_ip in addresses:
        direction = "outbound"
    elif destination_ip in addresses:
        direction = "inbound"
    else:
        direction = "unknown"

    timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
    flow_id = f"live_{uuid4().hex}"
    return FlowEvent(
        timestamp=timestamp,
        flow_id=flow_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        packets=1,
        bytes=len(packet),
        direction=direction,
        tcp_flags=tcp_flags,
        connection_completed=completed,
        dns_query=dns_query,
        dns_record_type=dns_record_type,
    )


def capture_events(
    stop_event: threading.Event,
    interface: str | None = None,
    bpf_filter: str = "ip or ip6",
) -> Iterator[FlowEvent]:
    """Yield passive events from an authorized interface until stopped."""
    try:
        from scapy.all import AsyncSniffer
    except ImportError as exc:
        raise RuntimeError(
            "Live capture requires Scapy. Install it with: "
            "python -m pip install -e 'backend[live]'"
        ) from exc

    events: queue.Queue[FlowEvent] = queue.Queue(maxsize=4096)
    local_addresses = _local_addresses()

    def on_packet(packet: object) -> None:
        event = packet_to_event(packet, local_addresses)
        if event is None:
            return
        try:
            events.put_nowait(event)
        except queue.Full:
            # Preserve bounded memory under packet bursts; the detector remains live.
            pass

    sniffer = AsyncSniffer(
        iface=interface or None,
        filter=bpf_filter,
        prn=on_packet,
        store=False,
    )
    sniffer.start()
    try:
        while not stop_event.is_set():
            try:
                yield events.get(timeout=0.25)
            except queue.Empty:
                continue
    finally:
        if sniffer.running:
            sniffer.stop()
