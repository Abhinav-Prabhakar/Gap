"""Deterministic hashing, redaction, ids and logging helpers."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import logging
import math
import re
import secrets
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, time, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Awaitable, Mapping, Sequence, TypeVar
from uuid import UUID

from .types import REDACTED, Logger

T = TypeVar("T")

__all__ = [
    "REDACTED",
    "canonical_json",
    "create_id",
    "create_logger",
    "deep_get",
    "format_duration",
    "has_scopes",
    "hash_value",
    "missing_scopes",
    "parse_path",
    "redact",
    "sha256_hex",
    "silent_logger",
    "to_jsonable",
    "maybe_await",
]

_CIRCULAR = "Cannot canonicalize a circular structure."
_SCOPE_SPLIT = re.compile(r"[^a-z0-9]+")
_BRACKET_PATH = re.compile(r"\[(\*|\d*)\]")


def _iso_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _model_dump(value: Any) -> Any | None:
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return dump(mode="json", by_alias=True)
        except TypeError:
            return dump()
    return None


def _normalize(value: Any, seen: set[int]) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        # JavaScript's JSON.stringify serialises 1.0 as "1". Match it so
        # approval ids and hashes are stable across language runtimes.
        if value.is_integer():
            return int(value)
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            return None
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return _iso_timestamp(value)
    if isinstance(value, (date, time)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, Enum):
        return _normalize(value.value, seen)

    dumped = _model_dump(value)
    if dumped is not None:
        return _normalize(dumped, seen)
    if is_dataclass(value) and not isinstance(value, type):
        return _normalize(asdict(value), seen)

    identity = id(value)
    if isinstance(value, (list, tuple)):
        if identity in seen:
            raise TypeError(_CIRCULAR)
        seen.add(identity)
        try:
            return [_normalize(item, seen) for item in value]
        finally:
            seen.discard(identity)
    if isinstance(value, (set, frozenset)):
        if identity in seen:
            raise TypeError(_CIRCULAR)
        seen.add(identity)
        try:
            items = [_normalize(item, seen) for item in value]
            return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
        finally:
            seen.discard(identity)
    if isinstance(value, Mapping):
        if identity in seen:
            raise TypeError(_CIRCULAR)
        seen.add(identity)
        try:
            result: dict[str, Any] = {}
            for key in sorted(value.keys(), key=lambda item: str(item)):
                result[str(key)] = _normalize(value[key], seen)
            return result
        finally:
            seen.discard(identity)
    raise TypeError(f"Cannot canonicalize value of type {type(value).__name__}.")


def canonical_json(value: Any) -> str:
    """Deterministic, compact JSON with sorted keys.

    Used for argument hashing, approval binding, idempotency keys and audit
    records. ``None`` survives; non-finite numbers become ``null``; datetimes
    become ISO-8601 UTC strings; integral floats serialise as integers to match
    JavaScript's number formatting.
    """
    return json.dumps(
        _normalize(value, set()),
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_hex(value: str | bytes) -> str:
    """SHA-256 digest as lowercase hex."""
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(payload).hexdigest()


def hash_value(value: Any) -> str:
    """Hash a value with :func:`canonical_json` and SHA-256."""
    return sha256_hex(canonical_json(value))


def create_id(prefix: str) -> str:
    """Generate an id such as ``apr_3f...`` with 96 bits of randomness."""
    return f"{prefix}_{secrets.token_hex(12)}"


def _scope_matches(granted: str, required: str) -> bool:
    if granted == "*" or granted == required:
        return True
    if granted.endswith(":*"):
        return required.startswith(granted[:-1])
    if granted.endswith("*"):
        return required.startswith(granted[:-1])
    return False


def has_scopes(granted: Sequence[str] | None, required: Sequence[str] | None) -> bool:
    """Every required scope must be covered by a granted scope."""
    if not required:
        return True
    available = granted or ()
    return all(
        any(_scope_matches(grant, scope) for grant in available) for scope in required
    )


def missing_scopes(
    granted: Sequence[str] | None, required: Sequence[str] | None
) -> list[str]:
    """Required scopes not covered by the grant."""
    available = granted or ()
    return [
        scope
        for scope in (required or ())
        if not any(_scope_matches(grant, scope) for grant in available)
    ]


def parse_path(path: str) -> list[str]:
    """Split a dot/bracket path into segments.

    ``items[].ssn``, ``items[*].ssn`` and ``items[2].ssn`` all become
    ``["items", "*", "ssn"]`` / ``["items", "2", "ssn"]``.
    """
    expanded = _BRACKET_PATH.sub(lambda match: f".{match.group(1) or '*'}", path)
    return [part.strip() for part in expanded.split(".") if part.strip()]


def deep_get(value: Any, path: str) -> Any:
    """Read a dot/bracket path, returning ``None`` when it is absent."""
    current = value
    for segment in parse_path(path):
        if current is None:
            return None
        if isinstance(current, (list, tuple)):
            if segment == "*":
                return current
            try:
                index = int(segment)
            except ValueError:
                return None
            if index < 0 or index >= len(current):
                return None
            current = current[index]
        elif isinstance(current, Mapping):
            current = current.get(segment)
        else:
            return None
    return current


def _redact_at(value: Any, segments: Sequence[str], index: int) -> Any:
    if index >= len(segments):
        return REDACTED
    segment = segments[index]
    if isinstance(value, list):
        if segment == "*":
            return [_redact_at(item, segments, index + 1) for item in value]
        try:
            position = int(segment)
        except ValueError:
            return value
        if position < 0 or position >= len(value):
            return value
        copy = list(value)
        copy[position] = _redact_at(copy[position], segments, index + 1)
        return copy
    if not isinstance(value, Mapping):
        return value
    if segment == "*":
        return {
            key: _redact_at(item, segments, index + 1) for key, item in value.items()
        }
    if segment not in value:
        return value
    copy = dict(value)
    copy[segment] = _redact_at(copy[segment], segments, index + 1)
    return copy


def redact(value: T, paths: Sequence[str] | None) -> T:
    """Deep-redact values at dot/bracket paths without mutating the source.

    Supports ``email``, ``cards[].number``, ``items[*].ssn`` and numeric
    indexes. Redacted leaves become ``"[REDACTED]"``.
    """
    if not paths:
        return value
    result: Any = value
    for path in paths:
        result = _redact_at(result, parse_path(path), 0)
    return result


def to_jsonable(value: Any, _seen: set[int] | None = None) -> Any:
    """Convert a Python value into JSON-serialisable primitives.

    Handles pydantic models, dataclasses, enums, datetimes, decimals, UUIDs,
    bytes, sets and nested containers. Unknown objects fall back to their
    ``__dict__`` or ``str`` representation.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Decimal):
        if not value.is_finite():
            return None
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, datetime):
        return _iso_timestamp(value)
    if isinstance(value, (date, time)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, Enum):
        return to_jsonable(value.value, _seen)

    dumped = _model_dump(value)
    if dumped is not None:
        return to_jsonable(dumped, _seen)
    if is_dataclass(value) and not isinstance(value, type):
        return to_jsonable(asdict(value), _seen)

    seen = _seen if _seen is not None else set()
    identity = id(value)
    if isinstance(value, (list, tuple)):
        if identity in seen:
            raise TypeError(_CIRCULAR)
        seen.add(identity)
        try:
            return [to_jsonable(item, seen) for item in value]
        finally:
            seen.discard(identity)
    if isinstance(value, (set, frozenset)):
        if identity in seen:
            raise TypeError(_CIRCULAR)
        seen.add(identity)
        try:
            items = [to_jsonable(item, seen) for item in value]
            return sorted(items, key=lambda item: canonical_json(item))
        finally:
            seen.discard(identity)
    if isinstance(value, Mapping):
        if identity in seen:
            raise TypeError(_CIRCULAR)
        seen.add(identity)
        try:
            return {str(key): to_jsonable(item, seen) for key, item in value.items()}
        finally:
            seen.discard(identity)
    if hasattr(value, "__dict__"):
        return to_jsonable(vars(value), seen)
    return str(value)


_LEVELS: dict[str, int] = {
    "debug": 10,
    "info": 20,
    "warn": 30,
    "error": 40,
}
_LOG_METHODS: dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "error": logging.ERROR,
}


class _GapLogger(Logger):
    """Small structured logger that forwards through :mod:`logging`."""

    def __init__(
        self,
        level: str,
        bindings: Mapping[str, Any],
        name: str = "gapmcp",
    ) -> None:
        self._level = level
        self._bindings = dict(bindings)
        self._logger = logging.getLogger(name)

    def _write(self, level: str, message: str, args: Sequence[Any]) -> None:
        if self._level == "silent" or _LEVELS[level] < _LEVELS.get(self._level, 20):
            return
        suffix = ""
        if args:
            try:
                suffix = " " + json.dumps(to_jsonable(list(args)), ensure_ascii=False)
            except (TypeError, ValueError):
                suffix = " " + " ".join(str(arg) for arg in args)
        prefix = ""
        if self._bindings:
            try:
                prefix = (
                    json.dumps(to_jsonable(self._bindings), ensure_ascii=False) + " "
                )
            except (TypeError, ValueError):
                prefix = ""
        self._logger.log(_LOG_METHODS[level], "%s%s%s", prefix, message, suffix)

    def debug(self, message: str, *args: Any) -> None:
        self._write("debug", message, args)

    def info(self, message: str, *args: Any) -> None:
        self._write("info", message, args)

    def warn(self, message: str, *args: Any) -> None:
        self._write("warn", message, args)

    def error(self, message: str, *args: Any) -> None:
        self._write("error", message, args)

    def child(self, bindings: Mapping[str, Any]) -> "Logger":
        return _GapLogger(
            self._level, {**self._bindings, **dict(bindings)}, self._logger.name
        )


def create_logger(
    level: str = "info",
    bindings: Mapping[str, Any] | None = None,
    *,
    name: str = "gapmcp",
) -> Logger:
    """Create a structured logger at ``debug``, ``info``, ``warn``, ``error``
    or ``silent``."""
    if level not in {*_LEVELS, "silent"}:
        raise ValueError(f"Unknown log level: {level!r}")
    return _GapLogger(level, bindings or {}, name)


silent_logger: Logger = _GapLogger("silent", {})
"""A logger that discards everything."""


def format_duration(milliseconds: float) -> str:
    """Best-effort human duration used in receipts and CLI output."""
    if milliseconds < 1000:
        return f"{round(milliseconds)}ms"
    if milliseconds < 60_000:
        return f"{milliseconds / 1000:.1f}s"
    return f"{round(milliseconds / 60_000)}m"


async def maybe_await(value: T | Awaitable[T]) -> T:
    """Await a value when it is awaitable, otherwise return it unchanged."""
    if inspect.isawaitable(value):
        return await value
    return value
