"""MCP server, request pipeline, meta-tools and HTTP / stdio transports."""

from __future__ import annotations

import asyncio
import inspect
import json
import math
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Iterable, Mapping, Sequence

from mcp import types as mcp_types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .action import Action
from .audit import MemoryAuditLog, create_audit_event
from .auth import (
    HmacApprovalGate,
    MemoryApprovalStore,
    PendingApproval,
    bearer_challenge,
    create_handoff_url,
    protected_resource_metadata,
)
from .errors import (
    GapError,
    approval_required,
    conflict,
    forbidden,
    internal,
    invalid_input,
    normalize_error,
    not_found,
    policy_denied,
    public_error_payload,
    rate_limited,
    timeout,
    unauthorized,
)
from .registry import ActionRegistry, to_tool_descriptor
from .schema import parse_value
from .search import search_actions
from .types import (
    ActionContext,
    AuthResult,
    CallRecord,
    Logger,
    PolicyDecision,
    Principal,
    ToolDescriptor,
)
from .utils import (
    create_id,
    hash_value,
    has_scopes,
    maybe_await,
    missing_scopes,
    redact,
    silent_logger,
    to_jsonable,
)

__all__ = [
    "CallStore",
    "GapServer",
    "GapServerOptions",
    "IdempotencyEntry",
    "MemoryIdempotencyStore",
    "RateLimit",
    "RateLimitResult",
    "TaskManager",
    "TaskRecord",
    "TokenBucketRateLimiter",
    "create_server",
]

_AUTH_STATE_KEY = "gapmcp.auth_result"
_DEFAULT_TIMEOUT_MS = 30_000
_TASK_TERMINAL = {"completed", "failed", "cancelled"}
_META_NAMES = frozenset(
    {
        "gap.search",
        "gap.tasks.get",
        "gap.tasks.cancel",
        "gap.receipts.get",
        "gap.undo",
        "gap.handoff",
    }
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _truthy_confirmation(value: Any) -> bool:
    return value is True


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class RateLimit:
    """Token-bucket configuration: ``limit`` calls per ``window_ms``."""

    limit: int
    window_ms: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.limit, bool)
            or not isinstance(self.limit, int)
            or self.limit <= 0
        ):
            raise invalid_input("Rate limit must be a positive integer.")
        if (
            isinstance(self.window_ms, bool)
            or not isinstance(self.window_ms, int)
            or self.window_ms <= 0
        ):
            raise invalid_input("Rate limit window_ms must be a positive integer.")


@dataclass(frozen=True, kw_only=True, slots=True)
class RateLimitResult:
    """The outcome of a rate-limit check."""

    allowed: bool
    retry_after_ms: float | None = None


@dataclass(kw_only=True, slots=True)
class _Bucket:
    tokens: float
    last_ms: float


class TokenBucketRateLimiter:
    """Per-key token bucket.

    A key can make ``limit`` calls per ``window_ms``; tokens refill
    continuously. State is in-process and should be replaced with a shared
    limiter when running multiple replicas.
    """

    def __init__(
        self,
        limit: int,
        window_ms: int,
        *,
        now: Callable[[], float] | None = None,
    ) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise invalid_input("Rate limit must be a positive integer.")
        if (
            isinstance(window_ms, bool)
            or not isinstance(window_ms, int)
            or window_ms <= 0
        ):
            raise invalid_input("Rate limit window_ms must be a positive integer.")
        self.limit = limit
        self.window_ms = window_ms
        self._now = now or (lambda: time.monotonic() * 1000)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> RateLimitResult:
        """Consume one token for ``key`` or report how long to wait."""
        with self._lock:
            now = self._now()
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=float(self.limit), last_ms=now)
                self._buckets[key] = bucket
            elapsed = max(0.0, now - bucket.last_ms)
            bucket.tokens = min(
                float(self.limit),
                bucket.tokens + elapsed * self.limit / self.window_ms,
            )
            bucket.last_ms = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return RateLimitResult(allowed=True)
            retry = math.ceil((1.0 - bucket.tokens) * self.window_ms / self.limit)
            return RateLimitResult(allowed=False, retry_after_ms=float(max(1, retry)))

    def reset(self, key: str | None = None) -> None:
        """Reset one bucket or all buckets."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


@dataclass(kw_only=True, slots=True)
class IdempotencyEntry:
    """One in-flight or completed idempotent call."""

    key: str
    created_at: float
    expires_at: float
    event: asyncio.Event = field(default_factory=asyncio.Event)
    status: str = "inflight"
    outcome: Any = None
    error: GapError | None = None


class MemoryIdempotencyStore:
    """In-process idempotency cache with TTL and in-flight deduplication.

    Concurrent callers for the same key wait on one execution and receive the
    same result. Successful results are replayed for ``ttl_ms`` (10 minutes by
    default); failures wake waiters but are not replayed after the call.
    """

    def __init__(
        self, *, ttl_ms: int = 10 * 60 * 1000, now: Callable[[], float] | None = None
    ) -> None:
        if isinstance(ttl_ms, bool) or not isinstance(ttl_ms, int) or ttl_ms <= 0:
            raise invalid_input("Idempotency ttl_ms must be a positive integer.")
        self.ttl_ms = ttl_ms
        self._now = now or time.monotonic
        self._entries: dict[str, IdempotencyEntry] = {}

    def _purge(self) -> None:
        now = self._now()
        for key, entry in list(self._entries.items()):
            if entry.status == "complete" and entry.expires_at <= now:
                self._entries.pop(key, None)

    def begin(self, key: str) -> tuple[IdempotencyEntry, bool]:
        """Return ``(entry, is_new)`` for a key."""
        self._purge()
        existing = self._entries.get(key)
        if existing is not None:
            return existing, False
        now = self._now()
        entry = IdempotencyEntry(
            key=key,
            created_at=now,
            expires_at=now + self.ttl_ms / 1000,
        )
        self._entries[key] = entry
        return entry, True

    def finish(
        self,
        entry: IdempotencyEntry,
        *,
        outcome: Any = None,
        error: GapError | None = None,
    ) -> None:
        """Complete an entry and wake every waiter."""
        entry.status = "complete"
        entry.outcome = outcome
        entry.error = error
        entry.expires_at = self._now() + self.ttl_ms / 1000
        entry.event.set()

    def fail(self, entry: IdempotencyEntry, error: GapError) -> None:
        """Wake waiters with an error and remove the entry so a retry can run."""
        entry.status = "complete"
        entry.error = error
        entry.event.set()
        self._entries.pop(entry.key, None)

    def abandon(self, entry: IdempotencyEntry, outcome: Any = None) -> None:
        """Wake waiters with an outcome that must not be replayed later."""
        entry.status = "complete"
        entry.outcome = outcome
        entry.event.set()
        self._entries.pop(entry.key, None)

    def clear(self) -> None:
        """Drop every entry."""
        self._entries.clear()

    async def wait(self, entry: IdempotencyEntry) -> None:
        """Wait until an in-flight entry completes."""
        await entry.event.wait()


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


@dataclass(kw_only=True, slots=True)
class TaskRecord:
    """A background action execution."""

    id: str
    action: str
    principal_id: str
    status: str = "working"
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    result: Any = None
    error: dict[str, Any] | None = None
    signal: Any = None
    task: asyncio.Task[Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "taskId": self.id,
            "action": self.action,
            "status": self.status,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "result": self.result,
            "error": self.error,
        }


class TaskManager:
    """In-memory task registry for actions declared with ``task=True``."""

    def __init__(self) -> None:
        self._tasks: dict[str, TaskRecord] = {}

    def create(self, action: str, principal_id: str, signal: Any = None) -> TaskRecord:
        """Create a task record without starting it."""
        record = TaskRecord(
            id=create_id("task"),
            action=action,
            principal_id=principal_id,
            signal=signal,
        )
        self._tasks[record.id] = record
        return record

    def start(
        self,
        record: TaskRecord,
        factory: Callable[[TaskRecord], Awaitable[Any]],
    ) -> TaskRecord:
        """Start a previously created task."""

        async def runner() -> None:
            try:
                record.result = await factory(record)
                record.status = "completed"
            except asyncio.CancelledError:
                record.status = "cancelled"
                record.error = {
                    "code": "TIMEOUT",
                    "message": "Task cancelled.",
                }
                raise
            except GapError as error:
                record.status = "failed"
                record.error = {"gapError": public_error_payload(error)}
            except Exception as error:  # pragma: no cover - defensive
                gap = normalize_error(error)
                record.status = "failed"
                record.error = {"gapError": public_error_payload(gap)}
            finally:
                record.updated_at = _now_iso()

        record.task = asyncio.create_task(runner())
        return record

    def get(self, task_id: str) -> TaskRecord | None:
        """Look up a task by id."""
        return self._tasks.get(task_id)

    def cancel(self, task_id: str) -> TaskRecord | None:
        """Cancel a running task; terminal tasks are returned unchanged."""
        record = self._tasks.get(task_id)
        if record is None:
            return None
        if record.status not in _TASK_TERMINAL:
            if record.signal is not None and hasattr(record.signal, "abort"):
                record.signal.abort()
            if record.task is not None:
                record.task.cancel()
        return record

    def list(self) -> list[TaskRecord]:
        """Snapshot of tasks, newest first."""
        return sorted(
            self._tasks.values(), key=lambda record: record.created_at, reverse=True
        )

    async def close(self) -> None:
        """Cancel every running task and wait for it to unwind."""
        pending = []
        for record in self._tasks.values():
            if record.status not in _TASK_TERMINAL and record.task is not None:
                if record.signal is not None and hasattr(record.signal, "abort"):
                    record.signal.abort()
                record.task.cancel()
                pending.append(record.task)
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------


@dataclass(kw_only=True, slots=True)
class _StoredReceipt:
    record: CallRecord
    input: Any
    output: Any


class CallStore:
    """Bounded store of successful call receipts (also used for undo)."""

    def __init__(self, limit: int = 500) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise invalid_input("Call store limit must be a non-negative integer.")
        self.limit = limit
        self._receipts: dict[str, _StoredReceipt] = {}
        self._order: list[str] = []

    def add(
        self, record: CallRecord, *, input: Any = None, output: Any = None
    ) -> CallRecord:
        """Store a receipt, evicting the oldest when the limit is reached."""
        self._receipts[record.id] = _StoredReceipt(
            record=record, input=input, output=output
        )
        self._order.append(record.id)
        if self.limit == 0:
            self._receipts.pop(record.id, None)
            self._order.remove(record.id)
        elif len(self._order) > self.limit:
            for stale in self._order[: len(self._order) - self.limit]:
                self._receipts.pop(stale, None)
            self._order = self._order[-self.limit :]
        return record

    def get(self, receipt_id: str) -> CallRecord | None:
        """Look up a public receipt."""
        entry = self._receipts.get(receipt_id)
        return entry.record if entry is not None else None

    def get_entry(self, receipt_id: str) -> _StoredReceipt | None:
        """Look up a receipt including the raw input/output used by undo."""
        return self._receipts.get(receipt_id)

    def list(self) -> list[CallRecord]:
        """Receipts, oldest first."""
        return [
            self._receipts[receipt_id].record
            for receipt_id in self._order
            if receipt_id in self._receipts
        ]

    def mark_undone(self, receipt_id: str) -> bool:
        """Mark a receipt undone; returns whether it existed."""
        entry = self._receipts.get(receipt_id)
        if entry is None:
            return False
        entry.record.undone = True
        return True

    def clear(self) -> None:
        """Remove every receipt."""
        self._receipts.clear()
        self._order.clear()


# ---------------------------------------------------------------------------
# Outcome helpers
# ---------------------------------------------------------------------------


@dataclass(kw_only=True, slots=True)
class _Outcome:
    text: str
    structured: Any = None
    is_error: bool = False
    cacheable: bool = True


def _text_for(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "OK"
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        return str(value)


def _success_outcome(value: Any, *, structured: bool = True) -> _Outcome:
    jsonable = to_jsonable(value)
    return _Outcome(
        text=_text_for(jsonable),
        structured=jsonable
        if structured and isinstance(jsonable, (dict, list))
        else None,
        is_error=False,
    )


def _error_outcome(error: GapError) -> _Outcome:
    payload = public_error_payload(error)
    text = f"{payload['message']} ({payload['code']})"
    if "details" in payload:
        try:
            text += "\n" + json.dumps(payload["details"], ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            pass
    return _Outcome(
        text=text,
        structured={"gapError": payload},
        is_error=True,
    )


# ---------------------------------------------------------------------------
# Options and server
# ---------------------------------------------------------------------------


@dataclass(kw_only=True, slots=True)
class GapServerOptions:
    """Configuration for :class:`GapServer`."""

    registry: ActionRegistry | Iterable[Action]
    name: str = "gapmcp"
    version: str = "0.1.0"
    instructions: str | None = None
    auth: Any | None = None
    policy: Any | None = None
    audit: Any | None = None
    logger: Logger | None = None
    approvals: HmacApprovalGate | None = None
    approval_store: MemoryApprovalStore | None = None
    rate_limit: RateLimit | Any | None = None
    idempotency: MemoryIdempotencyStore | Any | None = None
    session_mode: str = "stateful"
    base_url: str | None = None
    allow_elicitation: bool = False
    handoff_secret: str | None = None
    enable_tasks: bool = True
    call_store_limit: int = 500
    on_call: Callable[[CallRecord], Any] | None = None
    services: dict[str, Any] | None = None
    default_timeout_ms: int = _DEFAULT_TIMEOUT_MS
    stdio_principal: Principal | None = None
    authorization_servers: Sequence[str] | None = None
    scopes_supported: Sequence[str] | None = None
    cors_origins: Sequence[str] | None = None
    allowed_hosts: Sequence[str] | None = None
    allowed_origins: Sequence[str] | None = None
    enable_dns_rebinding_protection: bool = True

    def __post_init__(self) -> None:
        if self.session_mode not in {"stateful", "stateless"}:
            raise invalid_input('session_mode must be "stateful" or "stateless".')
        if not isinstance(self.enable_tasks, bool):
            raise invalid_input("enable_tasks must be a boolean.")
        if not isinstance(self.default_timeout_ms, int) or self.default_timeout_ms <= 0:
            raise invalid_input("default_timeout_ms must be a positive integer.")
        if self.call_store_limit < 0:
            raise invalid_input("call_store_limit must be non-negative.")


class _AllowPolicy:
    def evaluate(self, action: Action, args: Any, ctx: ActionContext) -> PolicyDecision:
        return PolicyDecision(decision="allow")


class _GapAuthMiddleware:
    """Authenticate HTTP requests before the MCP transport handles them."""

    def __init__(
        self,
        app: Any,
        *,
        auth: Any,
        challenge: str,
        exempt_paths: Sequence[str],
    ) -> None:
        self.app = app
        self.auth = auth
        self.challenge = challenge
        self.exempt = set(exempt_paths)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("path") in self.exempt
            or scope.get("method") == "OPTIONS"
        ):
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        try:
            result = await maybe_await(self.auth.authenticate(request))
        except Exception:
            result = None
        if result is None:
            response = JSONResponse(
                {"error": "unauthorized", "message": "Authentication required."},
                status_code=401,
                headers={"WWW-Authenticate": self.challenge},
            )
            await response(scope, receive, send)
            return
        scope.setdefault("state", {})[_AUTH_STATE_KEY] = result
        await self.app(scope, receive, send)


class GapServer:
    """An MCP server exposing a scope-filtered action registry.

    The pipeline is: authentication -> scope check -> policy -> rate limit ->
    input validation -> approval -> execute with timeout -> output validation
    -> redaction -> audit -> receipt. Errors are returned as MCP tool errors
    with ``structuredContent.gapError``.
    """

    def __init__(self, options: GapServerOptions) -> None:
        if not isinstance(options, GapServerOptions):
            raise TypeError("GapServer expects GapServerOptions; use create_server().")
        self.options = options
        self.registry = (
            options.registry
            if isinstance(options.registry, ActionRegistry)
            else ActionRegistry(options.registry)
        )
        reserved = [
            action.name
            for action in self.registry.list()
            if action.name == "gap" or action.name.startswith("gap.")
        ]
        if reserved:
            raise invalid_input(
                'The "gap." namespace is reserved for meta-tools: '
                + ", ".join(sorted(reserved))
                + "."
            )

        self.logger = options.logger or silent_logger
        self.policy = options.policy or _AllowPolicy()
        self.audit = options.audit if options.audit is not None else MemoryAuditLog()
        self.approval_store = options.approval_store or MemoryApprovalStore()
        self.idempotency = options.idempotency or MemoryIdempotencyStore()
        self.tasks = TaskManager()
        self.calls = CallStore(options.call_store_limit)
        self.receipts = self.calls
        self.rate_limiter: Any | None
        if options.rate_limit is None:
            self.rate_limiter = None
        elif isinstance(options.rate_limit, RateLimit):
            self.rate_limiter = TokenBucketRateLimiter(
                options.rate_limit.limit, options.rate_limit.window_ms
            )
        else:
            self.rate_limiter = options.rate_limit

        self._server: Server[Any] = Server(
            options.name,
            version=options.version,
            instructions=options.instructions,
        )
        self._server.add_request_handler(
            "tools/list", mcp_types.PaginatedRequestParams, self._on_list_tools
        )
        self._server.add_request_handler(
            "tools/call", mcp_types.CallToolRequestParams, self._on_call_tool
        )
        self._http_app: Starlette | None = None
        self._meta_descriptors = self._build_meta_descriptors()

    # -- public surface -----------------------------------------------------

    @property
    def server(self) -> Server[Any]:
        """The underlying lowlevel MCP server (useful for in-process clients)."""
        return self._server

    @property
    def lowlevel(self) -> Server[Any]:
        """Alias for :attr:`server`."""
        return self._server

    def visible_tools(self, principal: Principal | None = None) -> list[ToolDescriptor]:
        """Tool descriptors visible to a principal, without transport."""
        return self.list_tools(principal)

    def list_tools(self, principal: Principal | None = None) -> list[ToolDescriptor]:
        """Action and enabled meta-tool descriptors visible to a principal."""
        scopes = principal.scopes if principal is not None else ["*"]
        descriptors = [
            to_tool_descriptor(action) for action in self.registry.visible_to(scopes)
        ]
        descriptors.extend(
            descriptor
            for name, descriptor in self._meta_descriptors.items()
            if self._meta_enabled(name)
        )
        return sorted(descriptors, key=lambda descriptor: descriptor.name)

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        principal: Principal | None = None,
        scopes: Sequence[str] | None = None,
        meta: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Call a tool directly, bypassing the MCP transport but not the pipeline.

        Useful for tests and embedding. Returns
        ``{"isError", "text", "structured"}``.
        """
        principal = principal or Principal(
            id="anonymous", type="anonymous", scopes=["*"]
        )
        effective_scopes = (
            list(scopes) if scopes is not None else list(principal.scopes or [])
        )
        auth = AuthResult(
            principal=replace(principal, scopes=effective_scopes or None),
            scopes=effective_scopes,
        )
        try:
            outcome = await self._call_tool(
                None, name, dict(arguments or {}), dict(meta or {}), auth=auth
            )
        except GapError as error:
            outcome = _error_outcome(error)
        return {
            "isError": outcome.is_error,
            "text": outcome.text,
            "structured": outcome.structured,
        }

    def approve(self, approval_id: str, approved_by: str = "human") -> dict[str, Any]:
        """Approve a parked call by id (an ops/test helper, not an MCP tool)."""
        return self.approval_store.approve(approval_id, approved_by).to_dict()

    def pending_approvals(self) -> list[dict[str, Any]]:
        """Parked or approved calls, oldest first."""
        return [record.to_dict() for record in self.approval_store.list()]

    async def close(self) -> None:
        """Cancel tasks and close audit sinks."""
        await self.tasks.close()
        closer = getattr(self.audit, "close", None)
        if callable(closer):
            try:
                await maybe_await(closer())
            except Exception:
                pass

    # -- transports ---------------------------------------------------------

    async def run_stdio(self) -> None:
        """Serve MCP over stdin/stdout until the stream closes."""
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await self._server.run(
                read_stream,
                write_stream,
                self._server.create_initialization_options(),
            )

    async def serve_stdio(self) -> None:
        """Alias for :meth:`run_stdio`."""
        await self.run_stdio()

    def streamable_http_app(self) -> Starlette:
        """Return the Streamable HTTP ASGI app with health and metadata routes.

        ``/mcp`` is served by the MCP SDK; ``/health`` and
        ``/.well-known/oauth-protected-resource`` are unauthenticated.
        """
        if self._http_app is not None:
            return self._http_app

        sdk_app = self._server.streamable_http_app(
            streamable_http_path="/mcp",
            json_response=False,
            stateless_http=self.options.session_mode == "stateless",
            transport_security=self._transport_security(),
        )

        async def health(_: Request) -> JSONResponse:
            return JSONResponse(
                {
                    "status": "ok",
                    "name": self.options.name,
                    "version": self.options.version,
                    "tools": self.registry.size,
                }
            )

        async def metadata(_: Request) -> JSONResponse:
            document = self._protected_resource_metadata()
            if document is None:
                return JSONResponse({"error": "not_found"}, status_code=404)
            return JSONResponse(document)

        @asynccontextmanager
        async def lifespan(_: Starlette) -> Any:
            async with sdk_app.router.lifespan_context(sdk_app):
                yield

        routes = [
            Route("/health", health, methods=["GET"]),
            Route(
                "/.well-known/oauth-protected-resource",
                metadata,
                methods=["GET"],
            ),
            Mount("/", app=sdk_app),
        ]
        middleware: list[Middleware] = []
        if self.options.auth is not None:
            middleware.append(
                Middleware(
                    _GapAuthMiddleware,
                    auth=self.options.auth,
                    challenge=self._challenge(),
                    exempt_paths={
                        "/health",
                        "/.well-known/oauth-protected-resource",
                    },
                )
            )
        if self.options.cors_origins:
            middleware.append(
                Middleware(
                    CORSMiddleware,
                    allow_origins=list(self.options.cors_origins),
                    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                    allow_headers=["*"],
                    expose_headers=["Mcp-Session-Id"],
                    allow_credentials=True,
                )
            )
        self._http_app = Starlette(
            routes=routes, middleware=middleware, lifespan=lifespan
        )
        return self._http_app

    def app(self) -> Starlette:
        """Alias for :meth:`streamable_http_app`."""
        return self.streamable_http_app()

    def _transport_security(self) -> Any:
        from mcp.server.transport_security import TransportSecuritySettings

        if not self.options.enable_dns_rebinding_protection:
            return TransportSecuritySettings(enable_dns_rebinding_protection=False)
        if self.options.allowed_hosts is None and self.options.allowed_origins is None:
            # Let the SDK apply its localhost defaults.
            return None
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(
                self.options.allowed_hosts or ["127.0.0.1:*", "localhost:*", "[::1]:*"]
            ),
            allowed_origins=list(
                self.options.allowed_origins
                or ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
            ),
        )

    # -- MCP handlers -------------------------------------------------------

    async def _on_list_tools(
        self,
        ctx: ServerRequestContext[Any, Any],
        params: mcp_types.PaginatedRequestParams | None,
    ) -> mcp_types.ListToolsResult:
        del params
        try:
            auth = await self._resolve_auth(ctx)
        except GapError as error:
            raise MCPError(-32001, error.message) from error
        scopes = self._scopes(auth)
        tools = [
            to_tool_descriptor(action).to_mcp_tool()
            for action in self.registry.visible_to(scopes)
        ]
        tools.extend(
            descriptor.to_mcp_tool()
            for name, descriptor in self._meta_descriptors.items()
            if self._meta_enabled(name)
        )
        tools.sort(key=lambda tool: tool.name)
        return mcp_types.ListToolsResult(tools=tools)

    async def _on_call_tool(
        self,
        ctx: ServerRequestContext[Any, Any],
        params: mcp_types.CallToolRequestParams,
    ) -> mcp_types.CallToolResult:
        meta = dict(params.meta or {}) if params.meta else {}
        try:
            outcome = await self._call_tool(
                ctx, params.name, dict(params.arguments or {}), meta
            )
        except GapError as error:
            outcome = _error_outcome(error)
        except asyncio.CancelledError:
            raise
        except Exception as error:  # pragma: no cover - defensive
            gap = normalize_error(error)
            self.logger.error(
                "Unhandled tool error", {"action": params.name, "error": str(error)}
            )
            outcome = _error_outcome(gap)
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=outcome.text)],
            structured_content=outcome.structured,
            is_error=outcome.is_error,
        )

    # -- pipeline -----------------------------------------------------------

    async def _call_tool(
        self,
        ctx: ServerRequestContext[Any, Any] | None,
        name: str,
        args: dict[str, Any],
        meta: dict[str, Any],
        *,
        auth: AuthResult | None = None,
    ) -> _Outcome:
        auth = auth or await self._resolve_auth(ctx)
        if name in _META_NAMES and self._meta_enabled(name):
            return await self._call_meta(ctx, name, args, meta, auth)

        action = self.registry.get(name)
        if action is None:
            error = not_found(f'Unknown action "{name}".')
            await self._emit_audit(
                action=name,
                auth=auth,
                decision="error",
                args=args,
                error=error,
            )
            raise error

        context = self._make_context(auth, ctx, action_name=name)
        explicit_key = meta.get("idempotencyKey") or meta.get("gap/idempotencyKey")
        explicit_key = (
            explicit_key if isinstance(explicit_key, str) and explicit_key else None
        )
        if explicit_key:
            context.idempotency_key = explicit_key

        if action.idempotent or explicit_key:
            raw_key = explicit_key or hash_value({"action": name, "args": args})
            key = f"{auth.principal.id}:{name}:{raw_key}"
            entry, is_new = self.idempotency.begin(key)
            if not is_new:
                if entry.status == "complete":
                    if entry.error is not None:
                        await self._emit_audit(
                            action=name,
                            auth=auth,
                            ctx=context,
                            decision="error",
                            args=args,
                            error=entry.error,
                            metadata={"idempotentReplay": True},
                        )
                        raise entry.error
                    outcome = entry.outcome
                    await self._emit_audit(
                        action=name,
                        auth=auth,
                        ctx=context,
                        decision="allowed",
                        args=args,
                        result=outcome.structured,
                        metadata={"idempotentReplay": True},
                    )
                    return outcome
                await self.idempotency.wait(entry)
                if entry.error is not None:
                    raise entry.error
                return entry.outcome
            try:
                outcome = await self._execute_action(action, args, meta, context, ctx)
            except GapError as error:
                self.idempotency.fail(entry, error)
                raise
            except asyncio.CancelledError:
                self.idempotency.fail(
                    entry,
                    timeout("The action was cancelled."),
                )
                raise
            if outcome.cacheable:
                self.idempotency.finish(entry, outcome=outcome)
            else:
                # Pending approvals must not be replayed; a retry after the
                # human approves should execute instead of returning the same
                # approval request forever.
                self.idempotency.abandon(entry, outcome)
            return outcome

        return await self._execute_action(action, args, meta, context, ctx)

    async def _execute_action(
        self,
        action: Action,
        args: dict[str, Any],
        meta: dict[str, Any],
        ctx: ActionContext,
        mcp_ctx: ServerRequestContext[Any, Any] | None,
    ) -> _Outcome:
        auth = AuthResult(
            principal=ctx.principal,
            scopes=ctx.scopes,
        )
        approved = False

        async def fail(
            error: GapError,
            *,
            decision: str = "error",
            approval_id: str | None = None,
        ) -> None:
            nonlocal approved
            if not approved:
                await self._emit_audit(
                    action=action.name,
                    auth=auth,
                    ctx=ctx,
                    decision=decision,  # type: ignore[arg-type]
                    args=args,
                    error=error,
                    approval_id=approval_id,
                )
                approved = True

        try:
            missing = missing_scopes(ctx.scopes, action.scopes)
            if missing:
                error = forbidden(
                    "The principal is missing required scopes.",
                    {"missingScopes": missing},
                )
                await fail(error, decision="denied")
                raise error

            try:
                decision = await maybe_await(self.policy.evaluate(action, args, ctx))
            except GapError:
                raise
            except Exception as error:
                raise internal("Policy evaluation failed.", error) from error
            if not isinstance(decision, PolicyDecision):
                raise internal("Policy engine returned an invalid decision.")
            if decision.metadata and decision.metadata.get("dryRun") is True:
                ctx.dry_run = True

            if decision.decision == "deny":
                error = policy_denied(
                    decision.reason or "Blocked by policy.",
                    {
                        "code": decision.code,
                        "metadata": decision.metadata,
                    },
                )
                await fail(error, decision="denied")
                raise error

            if self.rate_limiter is not None:
                key = f"{ctx.principal.id}:{action.name}"
                try:
                    result = self.rate_limiter.check(key)
                except GapError:
                    raise
                except Exception as error:
                    raise internal("Rate limiter failed.", error) from error
                allowed, retry_after = _rate_result(result)
                if not allowed:
                    error = rate_limited(
                        "Rate limit exceeded for this tool.",
                        retry_after,
                    )
                    await fail(error, decision="denied")
                    raise error

            try:
                parsed = parse_value(action.input, args, "input")
            except GapError as error:
                await fail(error)
                raise

            needs_approval = decision.decision == "confirm"
            if not needs_approval and action.confirm:
                if action.confirm is True:
                    needs_approval = True
                elif callable(action.confirm):
                    try:
                        needs_approval = _truthy_confirmation(
                            await maybe_await(action.confirm(parsed, ctx))
                        )
                    except GapError:
                        raise
                    except Exception as error:
                        raise internal(
                            "The action confirmation check failed.", error
                        ) from error

            redactions = list(decision.redact_paths or [])

            if needs_approval:
                approval_token = meta.get("gap/approval") or meta.get("approvalToken")
                if isinstance(approval_token, str) and approval_token:
                    if self.options.approvals is None:
                        error = approval_required(
                            "Approval tokens are not configured on this server.",
                            {"retry": False},
                        )
                        await fail(error, decision="approval_required")
                        raise error
                    grant = await maybe_await(
                        self.options.approvals.verify(
                            approval_token,
                            action=action.name,
                            args=args,
                            principal_id=ctx.principal.id,
                        )
                    )
                    if grant is None:
                        error = approval_required(
                            "The approval token is invalid, expired or bound "
                            "to different arguments.",
                            {"retry": True},
                        )
                        await fail(error, decision="approval_required")
                        raise error
                    ctx.approval = grant

                elif (
                    ctx.approval is None
                    and self.approval_store.find_approved(
                        action=action.name,
                        principal_id=ctx.principal.id,
                        args_hash=hash_value(args),
                    )
                    is not None
                ):
                    record = self.approval_store.find_approved(
                        action=action.name,
                        principal_id=ctx.principal.id,
                        args_hash=hash_value(args),
                    )
                    assert record is not None
                    self.approval_store.consume(record.id)
                    ctx.approval = record.to_grant()

                elif ctx.approval is None and self.options.allow_elicitation:
                    elicited = await self._try_elicit(mcp_ctx, action, ctx, args)
                    if elicited is True:
                        record = self.approval_store.create(
                            action=action.name,
                            principal_id=ctx.principal.id,
                            args_hash=hash_value(args),
                        )
                        self.approval_store.approve(record.id, "mcp-client")
                        self.approval_store.consume(record.id)
                        ctx.approval = record.to_grant()
                    elif elicited is False:
                        error = approval_required(
                            "The human declined the approval request.",
                            {"retry": False},
                        )
                        await fail(error, decision="approval_required")
                        raise error

                if ctx.approval is None:
                    record = self.approval_store.create(
                        action=action.name,
                        principal_id=ctx.principal.id,
                        args_hash=hash_value(args),
                    )
                    await self._emit_audit(
                        action=action.name,
                        auth=auth,
                        ctx=ctx,
                        decision="approval_required",
                        args=args,
                        approval_id=record.id,
                    )
                    approved = True
                    return self._approval_outcome(action, record)

            if action.task and self.options.enable_tasks:
                record = self.tasks.create(action.name, ctx.principal.id, ctx.signal)

                async def run_task(task_record: TaskRecord) -> Any:
                    try:
                        outcome = await self._perform_execution(
                            action,
                            parsed,
                            args,
                            ctx,
                            redactions,
                            audit_success=False,
                        )
                    except GapError as error:
                        await self._emit_audit(
                            action=action.name,
                            auth=auth,
                            ctx=ctx,
                            decision="error",
                            args=args,
                            error=error,
                            metadata={"taskId": task_record.id},
                        )
                        raise
                    await self._emit_audit(
                        action=action.name,
                        auth=auth,
                        ctx=ctx,
                        decision="dry_run" if ctx.dry_run else "allowed",
                        args=args,
                        result=outcome.structured,
                        metadata={"taskId": task_record.id},
                    )
                    return (
                        outcome.structured
                        if outcome.structured is not None
                        else {"text": outcome.text}
                    )

                self.tasks.start(record, run_task)
                return _success_outcome(
                    {"taskId": record.id, "status": "working", "retry": True}
                )

            return await self._perform_execution(
                action, parsed, args, ctx, redactions, audit_success=True
            )
        except GapError as error:
            if not approved:
                decision = (
                    "denied"
                    if error.code
                    in {"FORBIDDEN", "POLICY_DENIED", "RATE_LIMITED", "UNAUTHENTICATED"}
                    else "approval_required"
                    if error.code == "APPROVAL_REQUIRED"
                    else "error"
                )
                await fail(error, decision=decision)
            raise
        except asyncio.CancelledError:
            ctx.signal.abort()
            raise
        except Exception as error:
            gap = normalize_error(error)
            self.logger.error(
                "Action failed",
                {"action": action.name, "error": str(error)},
            )
            if not approved:
                await fail(gap)
            raise gap from error

    async def _perform_execution(
        self,
        action: Action,
        parsed: Any,
        args: dict[str, Any],
        ctx: ActionContext,
        redactions: Sequence[str],
        *,
        audit_success: bool,
    ) -> _Outcome:
        started = time.perf_counter()
        timeout_ms = action.timeout_ms or self.options.default_timeout_ms
        try:
            result = await self._invoke(action.execute, parsed, ctx, timeout_ms)
        except GapError:
            raise
        except asyncio.TimeoutError:
            ctx.signal.abort()
            raise timeout("The action timed out.") from None
        except Exception as error:
            raise internal(f'Action "{action.name}" failed.', error) from error
        duration_ms = (time.perf_counter() - started) * 1000

        if action.output is not None:
            try:
                result = parse_value(action.output, result, "output")
            except GapError as error:
                raise internal("The action returned invalid output.", error) from error

        jsonable = to_jsonable(result)
        redacted_result = redact(jsonable, redactions)
        redacted_args = redact(to_jsonable(args), redactions)
        result_hash = hash_value(redacted_result)
        args_hash = hash_value(args)
        receipt_id = create_id("rcp")
        record = CallRecord(
            id=receipt_id,
            timestamp=_now_iso(),
            action=action.name,
            principal_id=ctx.principal.id,
            tenant_id=ctx.tenant_id,
            args=redacted_args,
            result=redacted_result,
            duration_ms=duration_ms,
            args_hash=args_hash,
            result_hash=result_hash,
            idempotency_key=ctx.idempotency_key,
            undo_available=action.undo is not None and self.calls.limit > 0,
        )
        self.calls.add(record, input=parsed, output=result)
        if self.options.on_call is not None:
            try:
                await maybe_await(self.options.on_call(record))
            except Exception:
                self.logger.error("on_call callback failed", {"action": action.name})
        if audit_success:
            await self._emit_audit(
                action=action.name,
                auth=AuthResult(principal=ctx.principal, scopes=ctx.scopes),
                ctx=ctx,
                decision="dry_run" if ctx.dry_run else "allowed",
                args=args,
                result=redacted_result,
                duration_ms=duration_ms,
                metadata={
                    "receiptId": receipt_id,
                    **(
                        {"approvalId": ctx.approval.id}
                        if ctx.approval is not None
                        else {}
                    ),
                },
            )
        structured = (
            redacted_result
            if action.output is not None or isinstance(redacted_result, (dict, list))
            else None
        )
        return _Outcome(
            text=_text_for(redacted_result),
            structured=structured,
            is_error=False,
        )

    async def _invoke(
        self,
        execute: Callable[[Any, ActionContext], Any],
        parsed: Any,
        ctx: ActionContext,
        timeout_ms: int,
    ) -> Any:
        loop = asyncio.get_running_loop()
        timer = loop.call_later(timeout_ms / 1000, ctx.signal.abort)
        try:
            if inspect.iscoroutinefunction(execute):
                return await asyncio.wait_for(
                    execute(parsed, ctx), timeout=timeout_ms / 1000
                )
            result = await asyncio.wait_for(
                asyncio.to_thread(execute, parsed, ctx),
                timeout=timeout_ms / 1000,
            )
            if inspect.isawaitable(result):
                return await asyncio.wait_for(result, timeout=timeout_ms / 1000)
            return result
        except asyncio.TimeoutError:
            ctx.signal.abort()
            raise timeout("The action timed out.") from None
        except asyncio.CancelledError:
            ctx.signal.abort()
            raise
        finally:
            timer.cancel()

    # -- meta tools ---------------------------------------------------------

    def _meta_enabled(self, name: str) -> bool:
        if name in {"gap.tasks.get", "gap.tasks.cancel"}:
            return self.options.enable_tasks and any(
                action.task for action in self.registry.list()
            )
        if name == "gap.search":
            return self.registry.size > 12
        if name == "gap.receipts.get":
            return self.calls.limit > 0
        if name == "gap.undo":
            return self.calls.limit > 0 and any(
                action.undo is not None for action in self.registry.list()
            )
        if name == "gap.handoff":
            return bool(self.options.handoff_secret) and any(
                action.ui is not None for action in self.registry.list()
            )
        return True

    def _build_meta_descriptors(self) -> dict[str, ToolDescriptor]:
        descriptors = {
            "gap.search": ToolDescriptor(
                name="gap.search",
                title="Search actions",
                description=(
                    "Search the action catalog by intent. Use this before "
                    "calling a specialized tool when you are unsure which "
                    "action fits."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Natural-language intent to search for.",
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50,
                            "description": "Maximum results to return.",
                        },
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
                annotations=_read_only_annotations("Search actions"),
                meta={"gap/meta": True},
            ),
            "gap.tasks.get": ToolDescriptor(
                name="gap.tasks.get",
                title="Get task",
                description=(
                    "Poll a background action task by id. Returns its status "
                    "and result when complete."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "taskId": {
                            "type": "string",
                            "description": "Task id returned by a task action.",
                        }
                    },
                    "required": ["taskId"],
                    "additionalProperties": False,
                },
                annotations=_read_only_annotations("Get task"),
                meta={"gap/meta": True},
            ),
            "gap.tasks.cancel": ToolDescriptor(
                name="gap.tasks.cancel",
                title="Cancel task",
                description=(
                    "Request cancellation of a running background task. The "
                    "task's abort signal is raised."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "taskId": {
                            "type": "string",
                            "description": "Task id to cancel.",
                        }
                    },
                    "required": ["taskId"],
                    "additionalProperties": False,
                },
                annotations=_read_only_annotations("Cancel task", read_only=False),
                meta={"gap/meta": True},
            ),
            "gap.receipts.get": ToolDescriptor(
                name="gap.receipts.get",
                title="Get receipt",
                description=(
                    "Fetch the receipt for a successful action call, including "
                    "redacted arguments and results."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "receiptId": {
                            "type": "string",
                            "description": "Receipt id from a prior call.",
                        }
                    },
                    "required": ["receiptId"],
                    "additionalProperties": False,
                },
                annotations=_read_only_annotations("Get receipt"),
                meta={"gap/meta": True},
            ),
            "gap.undo": ToolDescriptor(
                name="gap.undo",
                title="Undo action",
                description=(
                    "Run the best-effort inverse of a prior action that "
                    "declared an undo handler."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "receiptId": {
                            "type": "string",
                            "description": "Receipt id of the call to undo.",
                        },
                        "reason": {
                            "type": "string",
                            "description": "Optional reason for the undo.",
                        },
                    },
                    "required": ["receiptId"],
                    "additionalProperties": False,
                },
                annotations=_read_only_annotations("Undo action", read_only=False),
                meta={"gap/meta": True},
            ),
            "gap.handoff": ToolDescriptor(
                name="gap.handoff",
                title="Create handoff link",
                description=(
                    "Create a signed, expiring link that opens this action in "
                    "the app UI with its draft arguments."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "Action name with a UI binding.",
                        },
                        "args": {
                            "type": "object",
                            "description": "Draft arguments to hand to the human.",
                            "additionalProperties": True,
                        },
                        "ttlMs": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Link lifetime in milliseconds.",
                        },
                    },
                    "required": ["action"],
                    "additionalProperties": False,
                },
                annotations=_read_only_annotations("Create handoff link"),
                meta={"gap/meta": True},
            ),
        }
        return descriptors

    async def _call_meta(
        self,
        mcp_ctx: ServerRequestContext[Any, Any] | None,
        name: str,
        args: dict[str, Any],
        meta: dict[str, Any],
        auth: AuthResult,
    ) -> _Outcome:
        del meta
        ctx = self._make_context(auth, mcp_ctx, action_name=name)
        started = time.perf_counter()
        try:
            if name == "gap.search":
                result = self._meta_search(args, ctx)
            elif name == "gap.tasks.get":
                result = self._meta_task_get(args, ctx)
            elif name == "gap.tasks.cancel":
                result = self._meta_task_cancel(args, ctx)
            elif name == "gap.receipts.get":
                result = self._meta_receipt_get(args, ctx)
            elif name == "gap.undo":
                result = await self._meta_undo(args, ctx)
            elif name == "gap.handoff":
                result = self._meta_handoff(args, ctx)
            else:  # pragma: no cover - _META_NAMES is closed
                raise not_found(f'Unknown meta-tool "{name}".')
        except GapError as error:
            await self._emit_audit(
                action=name,
                auth=auth,
                ctx=ctx,
                decision=(
                    "denied"
                    if error.code in {"FORBIDDEN", "POLICY_DENIED", "UNAUTHENTICATED"}
                    else "error"
                ),
                args=args,
                error=error,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
            raise
        duration = (time.perf_counter() - started) * 1000
        await self._emit_audit(
            action=name,
            auth=auth,
            ctx=ctx,
            decision="allowed",
            args=args,
            result=result,
            duration_ms=duration,
        )
        return _success_outcome(result)

    def _meta_search(self, args: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        query = args.get("query")
        if not isinstance(query, str) or not query.strip():
            raise invalid_input("query must be a non-empty string.")
        limit = args.get("limit", 10)
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise invalid_input("limit must be an integer.")
        if limit < 1 or limit > 50:
            raise invalid_input("limit must be between 1 and 50.")
        results = search_actions(self.registry, query, limit=limit, scopes=ctx.scopes)
        return {
            "query": query,
            "count": len(results),
            "results": [result.to_dict() for result in results],
        }

    def _task_for(self, args: dict[str, Any], ctx: ActionContext) -> TaskRecord:
        task_id = args.get("taskId")
        if not isinstance(task_id, str) or not task_id:
            raise invalid_input("taskId must be a non-empty string.")
        record = self.tasks.get(task_id)
        if record is None or record.principal_id != ctx.principal.id:
            raise not_found(f'Unknown task "{task_id}".')
        return record

    def _meta_task_get(
        self, args: dict[str, Any], ctx: ActionContext
    ) -> dict[str, Any]:
        return self._task_for(args, ctx).to_dict()

    def _meta_task_cancel(
        self, args: dict[str, Any], ctx: ActionContext
    ) -> dict[str, Any]:
        record = self._task_for(args, ctx)
        if record.status not in _TASK_TERMINAL:
            self.tasks.cancel(record.id)
            record.status = "cancelled"
            record.updated_at = _now_iso()
            record.error = {
                "code": "TIMEOUT",
                "message": "Task cancelled.",
            }
        return record.to_dict()

    def _receipt_for(self, args: dict[str, Any], ctx: ActionContext) -> CallRecord:
        receipt_id = args.get("receiptId")
        if not isinstance(receipt_id, str) or not receipt_id:
            raise invalid_input("receiptId must be a non-empty string.")
        record = self.calls.get(receipt_id)
        if record is None or record.principal_id != ctx.principal.id:
            raise not_found(f'Unknown receipt "{receipt_id}".')
        return record

    def _meta_receipt_get(
        self, args: dict[str, Any], ctx: ActionContext
    ) -> dict[str, Any]:
        return self._receipt_for(args, ctx).to_dict()

    async def _meta_undo(
        self, args: dict[str, Any], ctx: ActionContext
    ) -> dict[str, Any]:
        record = self._receipt_for(args, ctx)
        entry = self.calls.get_entry(record.id)
        if entry is None:
            raise not_found(f'Unknown receipt "{record.id}".')
        if record.undone:
            raise conflict("This call was already undone.")
        action = self.registry.get(record.action)
        if action is None or action.undo is None:
            raise invalid_input(f'Action "{record.action}" does not support undo.')
        missing = missing_scopes(ctx.scopes, action.scopes)
        if missing:
            raise forbidden(
                "The principal is missing required scopes.",
                {"missingScopes": missing},
            )
        timeout_ms = action.timeout_ms or self.options.default_timeout_ms
        loop = asyncio.get_running_loop()
        timer = loop.call_later(timeout_ms / 1000, ctx.signal.abort)
        try:
            if inspect.iscoroutinefunction(action.undo):
                await asyncio.wait_for(
                    action.undo(entry.output, entry.input, ctx),
                    timeout=timeout_ms / 1000,
                )
            else:
                result = await asyncio.wait_for(
                    asyncio.to_thread(action.undo, entry.output, entry.input, ctx),
                    timeout=timeout_ms / 1000,
                )
                if inspect.isawaitable(result):
                    await asyncio.wait_for(result, timeout=timeout_ms / 1000)
        except asyncio.TimeoutError:
            ctx.signal.abort()
            raise timeout("The undo operation timed out.") from None
        except GapError:
            raise
        except Exception as error:
            raise internal("Undo failed.", error) from error
        finally:
            timer.cancel()
        self.calls.mark_undone(record.id)
        return {
            "receiptId": record.id,
            "action": record.action,
            "status": "undone",
            "reason": args.get("reason")
            if isinstance(args.get("reason"), str)
            else None,
        }

    def _meta_handoff(self, args: dict[str, Any], ctx: ActionContext) -> dict[str, Any]:
        name = args.get("action")
        if not isinstance(name, str) or not name:
            raise invalid_input("action must be a non-empty string.")
        action = self.registry.get(name)
        if action is None:
            raise not_found(f'Unknown action "{name}".')
        if not has_scopes(ctx.scopes, action.scopes):
            raise forbidden(
                "The principal is missing required scopes.",
                {"missingScopes": missing_scopes(ctx.scopes, action.scopes)},
            )
        if action.ui is None:
            raise invalid_input(f'Action "{name}" has no UI binding.')
        if not self.options.handoff_secret:
            raise invalid_input("Handoff is not configured on this server.")
        handoff_args = args.get("args")
        if handoff_args is None:
            handoff_args = {}
        if not isinstance(handoff_args, Mapping):
            raise invalid_input("args must be an object.")
        ttl = args.get("ttlMs", 5 * 60 * 1000)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
            raise invalid_input("ttlMs must be a positive integer.")
        route = action.ui.route or "/"
        url = create_handoff_url(
            base_url=self.options.base_url or "",
            action=action.name,
            args=dict(handoff_args),
            secret=self.options.handoff_secret,
            ttl_ms=ttl,
            path=route,
        )
        return {
            "url": url,
            "action": action.name,
            "route": route,
            "expiresInMs": ttl,
        }

    # -- elicitation --------------------------------------------------------

    async def _try_elicit(
        self,
        mcp_ctx: ServerRequestContext[Any, Any] | None,
        action: Action,
        ctx: ActionContext,
        args: dict[str, Any],
    ) -> bool | None:
        if not self.options.allow_elicitation or mcp_ctx is None:
            return None
        session = getattr(mcp_ctx, "session", None)
        if session is None or not getattr(session, "can_send_request", False):
            return None
        schema = {
            "type": "object",
            "properties": {
                "approve": {
                    "type": "boolean",
                    "title": "Approve",
                    "description": "Approve this action call.",
                }
            },
            "required": ["approve"],
        }
        try:
            result = await session.elicit_form(
                f"Approve {action.name} for {ctx.principal.id}?",
                schema,
                related_request_id=getattr(mcp_ctx, "request_id", None),
            )
        except Exception:
            return None
        if getattr(result, "action", None) != "accept":
            return False
        content = getattr(result, "content", None)
        return bool(isinstance(content, Mapping) and content.get("approve") is True)

    # -- auth / context -----------------------------------------------------

    def _scopes(self, auth: AuthResult) -> list[str]:
        if auth.scopes is not None:
            return list(auth.scopes)
        return list(auth.principal.scopes or [])

    def _anonymous_auth(self) -> AuthResult:
        principal = Principal(id="anonymous", type="anonymous", scopes=["*"])
        return AuthResult(principal=principal, scopes=["*"])

    async def _resolve_auth(
        self, ctx: ServerRequestContext[Any, Any] | None
    ) -> AuthResult:
        request = getattr(ctx, "request", None) if ctx is not None else None
        if request is not None:
            state = getattr(request, "scope", {}).get("state", {})
            if _AUTH_STATE_KEY in state:
                result = state[_AUTH_STATE_KEY]
                if result is None:
                    raise unauthorized()
                return result

        if self.options.auth is None:
            return self._anonymous_auth()

        if request is None:
            if self.options.stdio_principal is not None:
                principal = self.options.stdio_principal
                scopes = list(principal.scopes or [])
                return AuthResult(principal=principal, scopes=scopes)
            if self.options.auth is not None:
                # A configured auth provider means stdio/in-process callers
                # must opt in explicitly with stdio_principal.
                raise unauthorized("No stdio principal is configured for this server.")
            # Development default: anonymous with every scope.
            return self._anonymous_auth()

        try:
            result = await maybe_await(self.options.auth.authenticate(request))
        except Exception:
            result = None
        if result is None:
            raise unauthorized()
        return result

    def _make_context(
        self,
        auth: AuthResult,
        mcp_ctx: ServerRequestContext[Any, Any] | None,
        *,
        action_name: str,
    ) -> ActionContext:
        scopes = self._scopes(auth)
        principal = auth.principal
        if auth.scopes is not None and principal.scopes is None:
            principal = replace(principal, scopes=list(auth.scopes))
        trace_id = create_id("trace")
        child = getattr(self.logger, "child", None)
        logger = (
            child(
                {
                    "traceId": trace_id,
                    "action": action_name,
                    "principalId": principal.id,
                }
            )
            if callable(child)
            else self.logger
        )
        return ActionContext(
            principal=principal,
            scopes=scopes,
            tenant_id=principal.tenant_id,
            trace_id=trace_id,
            logger=logger,
            request=getattr(mcp_ctx, "request", None) if mcp_ctx else None,
            services=dict(self.options.services) if self.options.services else None,
        )

    def _challenge(self) -> str:
        provider = self.options.auth
        challenge = getattr(provider, "challenge", None)
        if callable(challenge):
            try:
                value = challenge()
            except Exception:
                value = None
            if value:
                metadata_url = None
                if self.options.base_url:
                    metadata_url = (
                        self.options.base_url.rstrip("/")
                        + "/.well-known/oauth-protected-resource"
                    )
                if metadata_url and "resource_metadata=" not in value:
                    return (
                        value
                        + ', resource_metadata="'
                        + metadata_url.replace("\\", "\\\\").replace('"', '\\"')
                        + '"'
                    )
                return value
        metadata_url = None
        if self.options.base_url:
            metadata_url = (
                self.options.base_url.rstrip("/")
                + "/.well-known/oauth-protected-resource"
            )
        return bearer_challenge(resource_metadata_url=metadata_url)

    def _protected_resource_metadata(self) -> dict[str, Any] | None:
        provider = self.options.auth
        getter = getattr(provider, "protected_resource_metadata", None)
        if callable(getter):
            try:
                document = getter()
            except Exception:
                document = None
            if document is not None:
                return document
        if self.options.base_url is None:
            return None
        scopes = (
            list(self.options.scopes_supported)
            if self.options.scopes_supported is not None
            else sorted(
                {scope for action in self.registry.list() for scope in action.scopes}
            )
        )
        return protected_resource_metadata(
            resource=self.options.base_url.rstrip("/") + "/mcp",
            authorization_servers=list(self.options.authorization_servers or []),
            scopes_supported=scopes,
        )

    # -- audit --------------------------------------------------------------

    async def _emit_audit(
        self,
        *,
        action: str,
        auth: AuthResult,
        decision: str,
        args: Any = None,
        result: Any = None,
        ctx: ActionContext | None = None,
        error: GapError | None = None,
        duration_ms: float | None = None,
        approval_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        args_hash = None
        result_hash = None
        if args is not None:
            try:
                args_hash = hash_value(args)
            except TypeError:
                args_hash = None
        if result is not None:
            try:
                result_hash = hash_value(result)
            except TypeError:
                result_hash = None
        event = create_audit_event(
            action=action,
            principal_id=auth.principal.id,
            tenant_id=auth.principal.tenant_id,
            decision=decision,
            args_hash=args_hash,
            result_hash=result_hash,
            duration_ms=duration_ms,
            scopes=self._scopes(auth),
            approval_id=approval_id
            or (ctx.approval.id if ctx is not None and ctx.approval else None),
            trace_id=ctx.trace_id if ctx is not None else None,
            error=(
                {
                    "code": error.code,
                    "message": (error.message if error.expose else "Internal error."),
                }
                if error is not None
                else None
            ),
            metadata=dict(metadata) if metadata else None,
        )
        try:
            await maybe_await(self.audit.record(event))
        except Exception as sink_error:
            self.logger.error(
                "Audit sink failed",
                {"action": action, "error": str(sink_error)},
            )

    # -- approval response --------------------------------------------------

    def _approval_outcome(self, action: Action, record: PendingApproval) -> _Outcome:
        approve_url = None
        if self.options.base_url:
            approve_url = self.options.base_url.rstrip("/") + "/approvals/" + record.id
        payload: dict[str, Any] = {
            "status": "approval_required",
            "approvalId": record.id,
            "action": action.name,
            "argsHash": record.args_hash,
            "expiresAt": record.expires_at,
            "retry": True,
        }
        if approve_url is not None:
            payload["approveUrl"] = approve_url
        return _Outcome(
            text=(
                f"Human approval is required for {action.name}. "
                f"Approval id: {record.id}. Retry this call after approval."
            ),
            structured=payload,
            is_error=False,
            cacheable=False,
        )


def _read_only_annotations(title: str, *, read_only: bool = True) -> dict[str, Any]:
    return {
        "title": title,
        "readOnlyHint": read_only,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }


def _rate_result(result: Any) -> tuple[bool, float | None]:
    if isinstance(result, RateLimitResult):
        return result.allowed, result.retry_after_ms
    if isinstance(result, tuple) and len(result) == 2:
        return bool(result[0]), (float(result[1]) if result[1] is not None else None)
    if isinstance(result, bool):
        return result, None
    allowed = getattr(result, "allowed", None)
    if isinstance(allowed, bool):
        retry = getattr(result, "retry_after_ms", None)
        return allowed, float(retry) if retry is not None else None
    raise TypeError("Rate limiter returned an unsupported result.")


def create_server(
    registry: ActionRegistry | Iterable[Action] | None = None,
    **options: Any,
) -> GapServer:
    """Create a :class:`GapServer` from a registry or an iterable of actions.

    Example::

        gap = create_server(registry=create_registry(create_invoice))
    """
    if registry is None:
        provided = options.pop("registry", None)
        if provided is None:
            raise invalid_input("create_server requires a registry.")
        registry = provided
    config = dict(options)
    config["registry"] = registry
    return GapServer(GapServerOptions(**config))
