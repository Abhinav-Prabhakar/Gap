"""The single error type that crosses an action boundary."""

from __future__ import annotations

import asyncio
from typing import Any, Mapping

GAP_ERROR_CODES: tuple[str, ...] = (
    "UNAUTHENTICATED",
    "FORBIDDEN",
    "INVALID_INPUT",
    "NOT_FOUND",
    "CONFLICT",
    "RATE_LIMITED",
    "APPROVAL_REQUIRED",
    "POLICY_DENIED",
    "TIMEOUT",
    "UNAVAILABLE",
    "INTERNAL",
)
"""Every stable error code an agent can receive."""

_DEFAULT_STATUS: dict[str, int] = {
    "UNAUTHENTICATED": 401,
    "FORBIDDEN": 403,
    "INVALID_INPUT": 400,
    "NOT_FOUND": 404,
    "CONFLICT": 409,
    "RATE_LIMITED": 429,
    "APPROVAL_REQUIRED": 428,
    "POLICY_DENIED": 403,
    "TIMEOUT": 504,
    "UNAVAILABLE": 503,
    "INTERNAL": 500,
}

_RETRYABLE = frozenset({"RATE_LIMITED", "UNAVAILABLE"})


class GapError(Exception):
    """A safe, machine-readable error for anything that crosses the boundary.

    Unknown application exceptions are wrapped as ``INTERNAL`` with
    ``expose=False`` so their message is not sent to the model.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str,
        status: int | None = None,
        details: Any = None,
        retryable: bool | None = None,
        expose: bool = True,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        if code not in _DEFAULT_STATUS:
            raise ValueError(f"Unknown Gap error code: {code!r}")
        self.message = message
        self.code = code
        self.status = status if status is not None else _DEFAULT_STATUS[code]
        self.details = details
        self.retryable = retryable if retryable is not None else code in _RETRYABLE
        self.expose = expose
        self.__cause__ = cause

    def to_dict(self) -> dict[str, Any]:
        """Public JSON shape, omitting unset details."""
        payload: dict[str, Any] = {
            "name": "GapError",
            "code": self.code,
            "message": self.message,
            "status": self.status,
            "retryable": self.retryable,
        }
        if self.details is not None:
            payload["details"] = self.details
        return payload

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


def is_gap_error(error: object) -> bool:
    """Type guard for :class:`GapError`."""
    return isinstance(error, GapError)


def unauthorized(message: str = "Authentication required.") -> GapError:
    return GapError(message, code="UNAUTHENTICATED")


def forbidden(
    message: str = "You do not have permission to perform this action.",
    details: Any = None,
) -> GapError:
    return GapError(message, code="FORBIDDEN", details=details)


def invalid_input(message: str = "Invalid input.", details: Any = None) -> GapError:
    return GapError(message, code="INVALID_INPUT", details=details)


def not_found(message: str = "Not found.") -> GapError:
    return GapError(message, code="NOT_FOUND")


def conflict(message: str = "Conflict.", details: Any = None) -> GapError:
    return GapError(message, code="CONFLICT", details=details)


def rate_limited(
    message: str = "Rate limit exceeded.", retry_after_ms: float | None = None
) -> GapError:
    return GapError(
        message,
        code="RATE_LIMITED",
        details=(None if retry_after_ms is None else {"retryAfterMs": retry_after_ms}),
    )


def approval_required(
    message: str = "This action requires human approval.", details: Any = None
) -> GapError:
    return GapError(message, code="APPROVAL_REQUIRED", details=details)


def policy_denied(message: str = "Blocked by policy.", details: Any = None) -> GapError:
    return GapError(message, code="POLICY_DENIED", details=details)


def timeout(message: str = "The action timed out.") -> GapError:
    return GapError(message, code="TIMEOUT")


def unavailable(message: str = "The action is temporarily unavailable.") -> GapError:
    return GapError(message, code="UNAVAILABLE")


def internal(
    message: str = "Internal error.", cause: BaseException | None = None
) -> GapError:
    return GapError(message, code="INTERNAL", expose=False, cause=cause)


def normalize_error(error: BaseException) -> GapError:
    """Turn anything thrown by application code into a :class:`GapError`."""
    if isinstance(error, GapError):
        return error
    if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        return timeout("The action was aborted or timed out.")
    if isinstance(error, asyncio.CancelledError):
        return timeout("The action was cancelled.")
    return internal(str(error) or error.__class__.__name__, error)


def status_for_error(error: object) -> int:
    """HTTP status for a raised value."""
    return error.status if isinstance(error, GapError) else 500


def public_error_payload(error: GapError) -> dict[str, Any]:
    """The error shape returned to a model, hiding non-exposed messages."""
    message = error.message if error.expose else "Internal error."
    payload: dict[str, Any] = {
        "name": "GapError",
        "code": error.code,
        "message": message,
        "status": error.status,
        "retryable": error.retryable,
    }
    if error.expose and error.details is not None:
        payload["details"] = error.details
    return payload


def error_headers(error: GapError, challenge: str | None = None) -> dict[str, str]:
    """Headers that should accompany an HTTP error response."""
    headers: dict[str, str] = {}
    if error.code == "UNAUTHENTICATED" and challenge:
        headers["WWW-Authenticate"] = challenge
    return headers


def error_from_payload(payload: Mapping[str, Any]) -> GapError:
    """Rehydrate a GapError from its public payload (used by clients/tests)."""
    return GapError(
        str(payload.get("message", "Error.")),
        code=str(payload.get("code", "INTERNAL")),
        status=int(payload["status"]) if "status" in payload else None,
        details=payload.get("details"),
        retryable=payload.get("retryable")
        if isinstance(payload.get("retryable"), bool)
        else None,
        expose=False if payload.get("message") == "Internal error." else True,
    )
