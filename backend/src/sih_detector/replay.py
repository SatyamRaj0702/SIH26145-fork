from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from .schemas import Alert, FlowEvent


def read_events(path: str | Path) -> Iterator[FlowEvent]:
    """Read normalized observations without writing to or contacting any network."""
    with Path(path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                yield FlowEvent.model_validate_json(line)
            except ValueError as exc:
                raise ValueError(f"Invalid event at {path}:{line_number}: {exc}") from exc


def replay(
    events: Iterable[FlowEvent],
    on_event: Callable[[FlowEvent], list[Alert]],
    on_alert: Callable[[Alert], None] | None = None,
    delay_seconds: float = 0.0,
) -> int:
    """Replay events incrementally and return the number of processed events."""
    processed = 0
    for event in events:
        alerts = on_event(event)
        if on_alert is not None:
            for alert in alerts:
                on_alert(alert)
        processed += 1
        if delay_seconds > 0:
            time.sleep(delay_seconds)
    return processed


def write_jsonl(path: str | Path, events: Iterable[FlowEvent]) -> None:
    with Path(path).open("w", encoding="utf-8") as target:
        for event in events:
            target.write(json.dumps(event.model_dump(mode="json")) + "\n")
