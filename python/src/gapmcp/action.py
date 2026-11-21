"""Action definitions, decorators and skill composition."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Mapping, Sequence

from .errors import GapError, invalid_input
from .schema import SchemaLike, parse_value
from .types import (
    ActionAnnotations,
    ActionContext,
    ActionExample,
    ActionUiBinding,
    RiskLevel,
)

__all__ = [
    "Action",
    "AnyAction",
    "define_action",
    "action",
    "define_actions",
    "define_skill",
    "is_action",
    "is_action_array",
    "run_action",
]


def _normalize_name(name: str) -> str:
    return " ".join(name.strip().split()).replace(" ", ".")


def _infer_description(function: Callable[..., Any]) -> str:
    doc = inspect.getdoc(function) or ""
    for line in doc.splitlines():
        if line.strip():
            return line.strip()
    return ""


@dataclass(kw_only=True, slots=True)
class Action:
    """A typed unit of agent capability.

    Actions are normally created with :func:`define_action`; constructing this
    class directly is supported for generated actions and importers.
    """

    name: str
    description: str
    execute: Callable[[Any, ActionContext], Any]
    input: SchemaLike | None = None
    output: SchemaLike | None = None
    scopes: list[str] = field(default_factory=list)
    risk: RiskLevel = "low"
    idempotent: bool = False
    confirm: bool | Callable[[Any, ActionContext], bool | Any] = False
    tags: list[str] = field(default_factory=list)
    examples: list[ActionExample] = field(default_factory=list)
    annotations: ActionAnnotations | None = None
    ui: ActionUiBinding | None = None
    undo: Callable[[Any, Any, ActionContext], Any] | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    timeout_ms: int | None = None
    task: bool = False
    deprecated: bool | str = False
    version: int = 1
    title: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise invalid_input("An action needs a non-empty string name.")
        self.name = _normalize_name(self.name)
        if not isinstance(self.description, str):
            raise invalid_input("An action description must be a string.")
        if not callable(self.execute):
            raise invalid_input("An action needs an execute function.")
        if self.risk not in {"low", "medium", "high", "critical"}:
            raise GapError(
                f"Invalid risk level {self.risk!r}.",
                code="INVALID_INPUT",
            )
        if self.timeout_ms is not None and (
            isinstance(self.timeout_ms, bool)
            or not isinstance(self.timeout_ms, int)
            or self.timeout_ms <= 0
        ):
            raise GapError(
                "Action timeout_ms must be a positive integer.",
                code="INVALID_INPUT",
            )
        if (
            isinstance(self.version, bool)
            or not isinstance(self.version, int)
            or self.version < 1
        ):
            raise invalid_input("Action version must be a positive integer.")
        if not isinstance(self.confirm, bool) and not callable(self.confirm):
            raise invalid_input("Action confirm must be a boolean or a callable.")
        if not isinstance(self.deprecated, (bool, str)):
            raise invalid_input("Action deprecated must be a boolean or a string.")
        self.scopes = list(self.scopes)
        self.tags = list(self.tags)
        self.examples = list(self.examples)
        self.meta = dict(self.meta)
        for label, values in (("scopes", self.scopes), ("tags", self.tags)):
            if any(not isinstance(value, str) or not value for value in values):
                raise invalid_input(f"Action {label} must contain non-empty strings.")


AnyAction = Action
"""Alias matching the TypeScript ``AnyAction`` type."""


def _execute_callable(
    fn: Callable[..., Any] | None,
    execute: Callable[..., Any] | None,
) -> Callable[..., Any] | None:
    if fn is not None and execute is not None:
        raise invalid_input("Pass either fn= or execute=, not both.")
    return execute if execute is not None else fn


def _build_action(
    *,
    function: Callable[..., Any] | None,
    name: str | None,
    description: str | None,
    input: SchemaLike | None,
    output: SchemaLike | None,
    scopes: Sequence[str] | None,
    risk: RiskLevel,
    idempotent: bool,
    confirm: bool | Callable[[Any, ActionContext], Any],
    tags: Sequence[str] | None,
    examples: Sequence[ActionExample] | None,
    annotations: ActionAnnotations | None,
    ui: ActionUiBinding | None,
    undo: Callable[[Any, Any, ActionContext], Any] | None,
    meta: dict[str, Any] | None,
    timeout_ms: int | None,
    task: bool,
    deprecated: bool | str,
    version: int,
    title: str | None,
    execute: Callable[..., Any] | None,
) -> Action:
    handler = _execute_callable(function, execute)
    if handler is None:
        raise invalid_input("An action needs an execute function.")
    final_name = name or getattr(handler, "__name__", "")
    if not final_name:
        raise invalid_input("An action needs a name.")
    final_description = (
        description if description is not None else _infer_description(handler)
    )
    return Action(
        name=final_name,
        description=final_description,
        execute=handler,
        input=input,
        output=output,
        scopes=list(scopes or []),
        risk=risk,
        idempotent=idempotent,
        confirm=confirm,
        tags=list(tags or []),
        examples=list(examples or []),
        annotations=annotations,
        ui=ui,
        undo=undo,
        meta=dict(meta or {}),
        timeout_ms=timeout_ms,
        task=task,
        deprecated=deprecated,
        version=version,
        title=title,
    )


def define_action(
    fn: Callable[..., Any] | Action | None = None,
    *,
    name: str | None = None,
    description: str | None = None,
    input: SchemaLike | None = None,
    output: SchemaLike | None = None,
    scopes: Sequence[str] | None = None,
    risk: RiskLevel = "low",
    idempotent: bool = False,
    confirm: bool | Callable[[Any, ActionContext], Any] = False,
    tags: Sequence[str] | None = None,
    examples: Sequence[ActionExample] | None = None,
    annotations: ActionAnnotations | None = None,
    ui: ActionUiBinding | None = None,
    undo: Callable[[Any, Any, ActionContext], Any] | None = None,
    meta: dict[str, Any] | None = None,
    timeout_ms: int | None = None,
    task: bool = False,
    deprecated: bool | str = False,
    version: int = 1,
    title: str | None = None,
    execute: Callable[..., Any] | None = None,
) -> Action | Callable[[Callable[..., Any]], Action]:
    """Define an action, as a decorator or a direct call.

    Three forms are supported::

        @define_action(name="invoices.create", description="...", input=Model)
        async def create_invoice(input, ctx): ...

        async def create_invoice(input, ctx): ...
        create_action = define_action(
            create_invoice,
            name="invoices.create",
            description="...",
        )

        template = define_action(name="invoices.create", description="...")
        create_action = define_action(template)(create_invoice)

    The decorated name is replaced by an :class:`Action` object. Actions are
    not callable themselves; use :func:`run_action` or a server to execute one.
    When ``name`` or ``description`` is omitted, the function name and first
    docstring line are used as a convenience; production actions should set
    both explicitly.
    """
    if isinstance(fn, Action):
        template = fn

        def decorate_existing(handler: Callable[..., Any]) -> Action:
            return replace(template, execute=handler)

        return decorate_existing

    if fn is not None:
        return _build_action(
            function=fn,
            name=name,
            description=description,
            input=input,
            output=output,
            scopes=scopes,
            risk=risk,
            idempotent=idempotent,
            confirm=confirm,
            tags=tags,
            examples=examples,
            annotations=annotations,
            ui=ui,
            undo=undo,
            meta=meta,
            timeout_ms=timeout_ms,
            task=task,
            deprecated=deprecated,
            version=version,
            title=title,
            execute=execute,
        )

    if execute is not None:
        # Direct call form: define_action(name=..., description=..., execute=fn)
        return _build_action(
            function=None,
            name=name,
            description=description,
            input=input,
            output=output,
            scopes=scopes,
            risk=risk,
            idempotent=idempotent,
            confirm=confirm,
            tags=tags,
            examples=examples,
            annotations=annotations,
            ui=ui,
            undo=undo,
            meta=meta,
            timeout_ms=timeout_ms,
            task=task,
            deprecated=deprecated,
            version=version,
            title=title,
            execute=execute,
        )

    def decorate(handler: Callable[..., Any]) -> Action:
        return _build_action(
            function=handler,
            name=name,
            description=description,
            input=input,
            output=output,
            scopes=scopes,
            risk=risk,
            idempotent=idempotent,
            confirm=confirm,
            tags=tags,
            examples=examples,
            annotations=annotations,
            ui=ui,
            undo=undo,
            meta=meta,
            timeout_ms=timeout_ms,
            task=task,
            deprecated=deprecated,
            version=version,
            title=title,
            execute=execute,
        )

    return decorate


action = define_action
"""Alias for :func:`define_action`, matching the ``action({...})`` style."""


def define_actions(*actions: Action) -> list[Action]:
    """Return the actions as a list, for use with ``ActionRegistry``."""
    return list(actions)


def is_action(value: Any) -> bool:
    """True when a value looks like an :class:`Action`."""
    if isinstance(value, Action):
        return True
    return (
        isinstance(value, Mapping)
        and isinstance(value.get("name"), str)
        and callable(value.get("execute"))
    )


def is_action_array(value: Any) -> bool:
    """True when every item looks like an action."""
    return isinstance(value, (list, tuple)) and all(is_action(item) for item in value)


async def run_action(action: AnyAction, input: Any, ctx: ActionContext) -> Any:
    """Run another action inside a skill.

    Input is validated with the child action's schema and the same context
    flows through, so composition cannot bypass policy or auth at the server
    boundary.
    """
    parsed = parse_value(action.input, input) if action.input else input
    result = action.execute(parsed, ctx)
    if inspect.isawaitable(result):
        return await result
    return result


def define_skill(
    fn: Callable[..., Any] | None = None,
    *,
    uses: Sequence[Action],
    name: str | None = None,
    description: str | None = None,
    input: SchemaLike | None = None,
    output: SchemaLike | None = None,
    scopes: Sequence[str] | None = None,
    risk: RiskLevel = "medium",
    idempotent: bool = False,
    confirm: bool | Callable[[Any, ActionContext], Any] = False,
    tags: Sequence[str] | None = None,
    examples: Sequence[ActionExample] | None = None,
    annotations: ActionAnnotations | None = None,
    ui: ActionUiBinding | None = None,
    undo: Callable[[Any, Any, ActionContext], Any] | None = None,
    meta: dict[str, Any] | None = None,
    timeout_ms: int | None = None,
    task: bool = False,
    deprecated: bool | str = False,
    version: int = 1,
    title: str | None = None,
) -> Action | Callable[[Callable[..., Any]], Action]:
    """Define a compound action that composes other actions.

    The skill's scopes are the union of ``scopes`` and every action in
    ``uses``. The handler receives ``(input, ctx, run)`` where
    ``await run(action, args)`` validates and executes a child action with the
    same delegated context. Like :func:`define_action`, this works as a
    decorator or a direct call.
    """
    actions = list(uses)
    merged_scopes: list[str] = []
    seen: set[str] = set()
    for scope in [
        *(item for child in actions for item in child.scopes),
        *(scopes or []),
    ]:
        if scope not in seen:
            seen.add(scope)
            merged_scopes.append(scope)

    def build(handler: Callable[..., Any]) -> Action:
        async def execute_skill(input_value: Any, ctx: ActionContext) -> Any:
            result = handler(
                input_value,
                ctx,
                lambda child, args: run_action(child, args, ctx),
            )
            if inspect.isawaitable(result):
                return await result
            return result

        execute_skill.__name__ = handler.__name__
        execute_skill.__doc__ = handler.__doc__
        return _build_action(
            function=execute_skill,
            name=name or handler.__name__,
            description=description,
            input=input,
            output=output,
            scopes=merged_scopes,
            risk=risk,
            idempotent=idempotent,
            confirm=confirm,
            tags=tags,
            examples=examples,
            annotations=annotations,
            ui=ui,
            undo=undo,
            meta=meta,
            timeout_ms=timeout_ms,
            task=task,
            deprecated=deprecated,
            version=version,
            title=title,
            execute=None,
        )

    if fn is not None:
        return build(fn)
    return build
