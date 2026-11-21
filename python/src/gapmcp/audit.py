"""In-memory and JSON Lines audit sinks."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import GapError, invalid_input
from .types import AuditEvent
from .utils import create_id

__all__ = [
    "JsonlAuditLog",
    "MemoryAuditLog",
    "create_audit_event",
]


def _timestamp(value: str | float | datetime | None) -> str:
    if value is None:
        moment = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    elif isinstance(value, (int, float)):
        moment = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    else:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def create_audit_event(
    *,
    action: str,
    principal_id: str,
    decision: str,
    tenant_id: str | None = None,
    args_hash: str | None = None,
    result_hash: str | None = None,
    duration_ms: float | None = None,
    scopes: list[str] | None = None,
    approval_id: str | None = None,
    trace_id: str | None = None,
    error: dict[str, str] | None = None,
    metadata: dict[str, Any] | None = None,
    id: str | None = None,
    timestamp: str | float | datetime | None = None,
) -> AuditEvent:
    """Fill in the generated fields of an audit event."""
    return AuditEvent(
        id=id or create_id("evt"),
        timestamp=_timestamp(timestamp),
        action=action,
        principal_id=principal_id,
        decision=decision,  # type: ignore[arg-type]
        tenant_id=tenant_id,
        args_hash=args_hash,
        result_hash=result_hash,
        duration_ms=duration_ms,
        scopes=list(scopes) if scopes is not None else None,
        approval_id=approval_id,
        trace_id=trace_id,
        error=dict(error) if error is not None else None,
        metadata=dict(metadata) if metadata is not None else None,
    )


class MemoryAuditLog:
    """In-memory audit sink useful for tests and local inspectors."""

    def __init__(self, max: int | None = None) -> None:
        if max is not None and (
            isinstance(max, bool) or not isinstance(max, int) or max < 0
        ):
            raise invalid_input("Audit log max must be a non-negative integer.")
        self._max = max
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        """Append one event, evicting oldest entries when bounded."""
        if self._max == 0:
            return
        self.events.append(event)
        if self._max is not None and len(self.events) > self._max:
            del self.events[: len(self.events) - self._max]

    def list(self) -> list[AuditEvent]:
        """Snapshot of recorded events, oldest first."""
        return list(self.events)

    def clear(self) -> None:
        """Remove every recorded event."""
        self.events.clear()


class JsonlAuditLog:
    """Append-only JSON Lines audit sink.

    Each event is one JSON object per line. The parent directory is created
    recursively and the file is opened with owner-only permissions.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        text = os.fspath(path)
        if not text.strip():
            raise invalid_input("Audit log path must not be empty.")
        self.path = Path(text)
        self._lock = threading.Lock()
        self._handle: Any | None = None
        self._closed = False
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _open(self) -> Any:
        if self._handle is None:
            descriptor = os.open(
                self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600
            )
            self._handle = os.fdopen(descriptor, "a", encoding="utf-8")
        return self._handle

    def record(self, event: AuditEvent) -> None:
        """Append one event and flush it to disk."""
        if self._closed:
            raise GapError("Audit log is closed.", code="INTERNAL", expose=False)
        try:
            line = json.dumps(event.to_dict(), ensure_ascii=False)
        except (TypeError, ValueError) as error:
            raise invalid_input("Audit event is not JSON-serializable.") from error
        with self._lock:
            try:
                handle = self._open()
                handle.write(line + "\n")
                handle.flush()
            except OSError as error:
                raise GapError(
                    "Failed to write the audit log.",
                    code="INTERNAL",
                    expose=False,
                    cause=error,
                ) from error

    def close(self) -> None:
        """Flush and close the underlying file."""
        with self._lock:
            self._closed = True
            if self._handle is not None:
                try:
                    self._handle.close()
                finally:
                    self._handle = None

    def __enter__(self) -> "JsonlAuditLog":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
