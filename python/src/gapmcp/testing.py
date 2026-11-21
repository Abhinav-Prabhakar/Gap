"""Test helpers for actions and Gap servers."""

from __future__ import annotations

import inspect
from typing import Any, Mapping, Sequence

from .action import Action
from .schema import parse_value
from .server import GapServer
from .types import AbortSignal, ActionContext, Principal
from .utils import create_id, silent_logger

__all__ = [
    "call_action",
    "call_tool",
    "test_context",
    "test_principal",
]


def test_principal(
    overrides: Mapping[str, Any] | None = None, **kwargs: Any
) -> Principal:
    """A principal suitable for unit tests; all scopes are granted.

    Accepts a mapping, keyword overrides, or both.
    """
    values: dict[str, Any] = {
        "id": "usr_test",
        "type": "user",
        "name": "Test User",
        "email": "test@example.com",
        "scopes": ["*"],
    }
    values.update(dict(overrides or {}))
    values.update(kwargs)
    values["metadata"] = dict(values.get("metadata") or {})
    return Principal(**values)


def test_context(
    overrides: Mapping[str, Any] | None = None, **kwargs: Any
) -> ActionContext:
    """A fully formed action context for direct action tests.

    Accepts a mapping, keyword overrides, or both, for example
    ``test_context(principal=Principal(id="usr_1", scopes=["*"]))``.
    """
    values = dict(overrides or {})
    values.update(kwargs)
    principal = values.pop("principal", None) or test_principal()
    scopes = values.pop("scopes", None)
    if scopes is None:
        scopes = list(principal.scopes or [])
    signal = values.pop("signal", None)
    if signal is None:
        signal = AbortSignal()
    logger = values.pop("logger", None)
    if logger is None:
        logger = silent_logger
    return ActionContext(
        principal=principal,
        scopes=scopes,
        tenant_id=values.pop("tenant_id", principal.tenant_id),
        dry_run=values.pop("dry_run", False),
        idempotency_key=values.pop("idempotency_key", None),
        approval=values.pop("approval", None),
        signal=signal,
        trace_id=values.pop("trace_id", None) or create_id("trace"),
        logger=logger,
        request=values.pop("request", None),
        services=values.pop("services", None),
    )


async def call_action(
    action: Action,
    args: Any,
    overrides: Mapping[str, Any] | None = None,
) -> Any:
    """Validate and execute an action directly, without the MCP layer."""
    parsed = parse_value(action.input, args) if action.input else args
    result = action.execute(parsed, test_context(overrides))
    if inspect.isawaitable(result):
        return await result
    return result


async def call_tool(
    server: GapServer,
    name: str,
    args: Mapping[str, Any] | None = None,
    *,
    principal: Principal | None = None,
    scopes: Sequence[str] | None = None,
    meta: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Call a tool through a Gap server's pipeline and return a public result."""
    return await server.call_tool(
        name,
        args,
        principal=principal,
        scopes=scopes,
        meta=meta,
    )
