"""Shared types for the Gap Python runtime.

The names mirror the TypeScript core where it is practical. Python code uses
``snake_case`` attributes; wire-facing serialisers emit the camelCase names used
by the TypeScript packages and MCP so the two implementations can interoperate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Literal, Mapping, Protocol, Sequence

JsonSchema = dict[str, Any]
"""A JSON Schema document (draft 2020-12 compatible)."""

RiskLevel = Literal["low", "medium", "high", "critical"]
PrincipalType = Literal["user", "service", "anonymous"]
PolicyDecisionName = Literal["allow", "deny", "confirm"]
AuditDecision = Literal["allowed", "denied", "error", "approval_required", "dry_run"]

REDACTED = "[REDACTED]"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _without_none(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}


class AbortSignal:
    """A small, dependency-free cancellation signal.

    Actions receive one on :class:`ActionContext` and should check
    :attr:`aborted` (or call :meth:`raise_if_aborted`) around expensive work.
    The server aborts the signal when an action times out or its task is
    cancelled.
    """

    __slots__ = ("_aborted", "_callbacks")

    def __init__(self) -> None:
        self._aborted = False
        self._callbacks: list[Callable[[], None]] = []

    @property
    def aborted(self) -> bool:
        """Whether cancellation was requested."""
        return self._aborted

    def abort(self) -> None:
        """Request cancellation and run registered callbacks once."""
        if self._aborted:
            return
        self._aborted = True
        for callback in list(self._callbacks):
            try:
                callback()
            except Exception:
                # Cancellation callbacks are best-effort bookkeeping.
                pass
        self._callbacks.clear()

    def add_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback, running it immediately if already aborted."""
        if self._aborted:
            callback()
            return
        self._callbacks.append(callback)

    def raise_if_aborted(self) -> None:
        """Raise :class:`RuntimeError` when cancellation was requested."""
        if self._aborted:
            raise RuntimeError("The action was aborted.")


class Logger(Protocol):
    """Structured logger interface used by actions and the server."""

    def debug(self, message: str, *args: Any) -> None: ...

    def info(self, message: str, *args: Any) -> None: ...

    def warn(self, message: str, *args: Any) -> None: ...

    def error(self, message: str, *args: Any) -> None: ...

    def child(self, bindings: Mapping[str, Any]) -> "Logger": ...


@dataclass(kw_only=True, slots=True)
class Principal:
    """The identity an action runs as.

    Gap never uses ambient service credentials: every invocation carries the
    principal the action is executed for.
    """

    id: str
    type: PrincipalType | None = None
    tenant_id: str | None = None
    scopes: list[str] | None = None
    email: str | None = None
    name: str | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a camelCase wire representation, omitting unset fields."""
        return _without_none(
            {
                "id": self.id,
                "type": self.type,
                "tenantId": self.tenant_id,
                "scopes": list(self.scopes) if self.scopes is not None else None,
                "email": self.email,
                "name": self.name,
                "metadata": dict(self.metadata) if self.metadata is not None else None,
            }
        )


@dataclass(kw_only=True, slots=True)
class AuthResult:
    """A successful authentication result."""

    principal: Principal
    token: str | None = None
    client_id: str | None = None
    scopes: list[str] | None = None
    expires_at: int | None = None
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return _without_none(
            {
                "principal": self.principal.to_dict(),
                "token": self.token,
                "clientId": self.client_id,
                "scopes": list(self.scopes) if self.scopes is not None else None,
                "expiresAt": self.expires_at,
                "extra": dict(self.extra) if self.extra is not None else None,
            }
        )


@dataclass(kw_only=True, slots=True)
class ApprovalGrant:
    """A signed grant proving a human approved one specific invocation."""

    id: str
    action: str
    args_hash: str
    approved_by: str
    issued_at: int
    expires_at: int
    scope: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _without_none(
            {
                "id": self.id,
                "action": self.action,
                "argsHash": self.args_hash,
                "approvedBy": self.approved_by,
                "issuedAt": self.issued_at,
                "expiresAt": self.expires_at,
                "scope": self.scope,
            }
        )


@dataclass(kw_only=True, slots=True)
class ActionContext:
    """Per-invocation context handed to actions."""

    principal: Principal
    scopes: list[str] = field(default_factory=list)
    tenant_id: str | None = None
    dry_run: bool = False
    idempotency_key: str | None = None
    approval: ApprovalGrant | None = None
    signal: AbortSignal = field(default_factory=AbortSignal)
    trace_id: str = ""
    span: Any | None = None
    logger: Logger | None = None
    request: Any | None = None
    services: dict[str, Any] | None = None


@dataclass(kw_only=True, slots=True)
class ActionUiBinding:
    """Describes how a human or browser agent performs the same action."""

    route: str | None = None
    action: str | None = None
    fields: dict[str, str] | None = None
    submit: str | None = None
    result: str | None = None
    wait_for: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _without_none(
            {
                "route": self.route,
                "action": self.action,
                "fields": dict(self.fields) if self.fields is not None else None,
                "submit": self.submit,
                "result": self.result,
                "waitFor": self.wait_for,
            }
        )


@dataclass(kw_only=True, slots=True)
class ActionExample:
    """An example invocation shown to planners and evals."""

    input: Any
    description: str | None = None


@dataclass(kw_only=True, slots=True)
class ActionAnnotations:
    """MCP tool annotations, using protocol names."""

    title: str | None = None
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    open_world_hint: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return _without_none(
            {
                "title": self.title,
                "readOnlyHint": self.read_only_hint,
                "destructiveHint": self.destructive_hint,
                "idempotentHint": self.idempotent_hint,
                "openWorldHint": self.open_world_hint,
            }
        )


@dataclass(kw_only=True, slots=True)
class ToolDescriptor:
    """The MCP-facing description of an action."""

    name: str
    description: str
    input_schema: JsonSchema
    title: str | None = None
    output_schema: JsonSchema | None = None
    annotations: dict[str, Any] | None = None
    meta: dict[str, Any] | None = None

    def to_mcp_tool(self) -> Any:
        """Convert to an ``mcp.types.Tool``.

        Imported lazily so the type module stays usable without the MCP SDK
        (for example in a schema-only script).
        """
        from mcp import types as mcp_types

        annotations = (
            mcp_types.ToolAnnotations.model_validate(self.annotations)
            if self.annotations is not None
            else None
        )
        return mcp_types.Tool(
            name=self.name,
            title=self.title,
            description=self.description,
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            annotations=annotations,
            meta=self.meta,
        )


@dataclass(kw_only=True, slots=True)
class RegistryIssue:
    """A contract-check finding produced by :meth:`ActionRegistry.validate`."""

    level: Literal["error", "warn"]
    code: str
    message: str
    action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _without_none(
            {
                "level": self.level,
                "code": self.code,
                "action": self.action,
                "message": self.message,
            }
        )


@dataclass(kw_only=True, slots=True)
class ValidationIssue:
    """One schema validation problem."""

    path: str
    message: str
    code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _without_none(
            {"path": self.path, "message": self.message, "code": self.code}
        )


@dataclass(kw_only=True, slots=True)
class ValidationResult:
    """Result of validating a value against an action schema."""

    success: bool
    data: Any = None
    issues: list[ValidationIssue] = field(default_factory=list)


@dataclass(kw_only=True, slots=True)
class PolicyDecision:
    """A policy engine's answer for one invocation."""

    decision: PolicyDecisionName
    reason: str | None = None
    code: str | None = None
    redact_paths: list[str] | None = None
    limits: dict[str, float] | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return _without_none(
            {
                "decision": self.decision,
                "reason": self.reason,
                "code": self.code,
                "redactPaths": list(self.redact_paths)
                if self.redact_paths is not None
                else None,
                "limits": dict(self.limits) if self.limits is not None else None,
                "metadata": dict(self.metadata) if self.metadata is not None else None,
            }
        )


@dataclass(kw_only=True, slots=True)
class AuditEvent:
    """One auditable decision in the request pipeline."""

    id: str
    timestamp: str
    action: str
    principal_id: str
    decision: AuditDecision
    tenant_id: str | None = None
    args_hash: str | None = None
    result_hash: str | None = None
    duration_ms: float | None = None
    scopes: list[str] | None = None
    approval_id: str | None = None
    trace_id: str | None = None
    error: dict[str, str] | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise with the camelCase names used by the TS audit sink."""
        return _without_none(
            {
                "id": self.id,
                "timestamp": self.timestamp,
                "action": self.action,
                "principalId": self.principal_id,
                "tenantId": self.tenant_id,
                "decision": self.decision,
                "argsHash": self.args_hash,
                "resultHash": self.result_hash,
                "durationMs": self.duration_ms,
                "scopes": list(self.scopes) if self.scopes is not None else None,
                "approvalId": self.approval_id,
                "traceId": self.trace_id,
                "error": dict(self.error) if self.error is not None else None,
                "metadata": dict(self.metadata) if self.metadata is not None else None,
            }
        )


@dataclass(kw_only=True, slots=True)
class CallRecord:
    """A recorded call, also used as an undo receipt."""

    id: str
    timestamp: str
    action: str
    principal_id: str
    tenant_id: str | None = None
    args: Any = None
    result: Any = None
    error: dict[str, Any] | None = None
    duration_ms: float | None = None
    args_hash: str | None = None
    result_hash: str | None = None
    idempotency_key: str | None = None
    undo_available: bool = False
    undone: bool = False

    def to_dict(self) -> dict[str, Any]:
        return _without_none(
            {
                "id": self.id,
                "receiptId": self.id,
                "timestamp": self.timestamp,
                "action": self.action,
                "principalId": self.principal_id,
                "tenantId": self.tenant_id,
                "args": self.args,
                "result": self.result,
                "error": self.error,
                "durationMs": self.duration_ms,
                "argsHash": self.args_hash,
                "resultHash": self.result_hash,
                "idempotencyKey": self.idempotency_key,
                "undoAvailable": self.undo_available,
                "undone": self.undone,
            }
        )


@dataclass(kw_only=True, slots=True)
class ActionFilter:
    """Optional filter applied by registry listing helpers."""

    names: Sequence[str] | None = None
    namespace: str | None = None
    tags: Sequence[str] | None = None
    scopes: Sequence[str] | None = None
    include: Callable[[Any], bool] | None = None


class AuthProvider(Protocol):
    """Transport-agnostic authentication provider."""

    async def authenticate(self, request: Any) -> AuthResult | None: ...

    def challenge(self) -> str: ...

    def protected_resource_metadata(self) -> dict[str, Any] | None: ...


class PolicyEngine(Protocol):
    """Interface for custom policy engines."""

    def evaluate(
        self, action: Any, args: Any, ctx: ActionContext
    ) -> PolicyDecision | Awaitable[PolicyDecision]: ...


class ApprovalGate(Protocol):
    """Issues and verifies approval tokens."""

    def issue(
        self,
        *,
        action: str,
        args: Any,
        principal_id: str,
        ttl_ms: int | None = None,
    ) -> Any: ...

    def verify(
        self, token: str, *, action: str, args: Any, principal_id: str
    ) -> ApprovalGrant | None | Awaitable[ApprovalGrant | None]: ...


class AuditSink(Protocol):
    """Receives audit events."""

    def record(self, event: AuditEvent) -> None | Awaitable[None]: ...
