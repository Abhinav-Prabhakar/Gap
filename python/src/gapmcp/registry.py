"""Scope-aware action registry and MCP tool descriptors."""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, Sequence

from .action import Action
from .errors import GapError, invalid_input
from .schema import (
    is_object_schema,
    schema_paths_without_descriptions,
    to_input_json_schema,
    to_output_json_schema,
)
from .types import (
    ActionFilter,
    RegistryIssue,
    ToolDescriptor,
)
from .utils import has_scopes

__all__ = [
    "ActionRegistry",
    "create_registry",
    "to_tool_descriptor",
]

_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$")
_SCOPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9:_-]*$")
_DESTRUCTIVE_VERBS = re.compile(
    r"(^|[.:_-])(delete|remove|destroy|refund|charge|transfer|send|cancel|revoke|drop|purge)([.:_-]|$)",
    re.IGNORECASE,
)


def _matches_filter(action: Action, filter: ActionFilter | None) -> bool:
    if filter is None:
        return True
    if filter.names is not None and action.name not in filter.names:
        return False
    if filter.namespace is not None and not action.name.startswith(
        f"{filter.namespace}."
    ):
        return False
    if filter.tags:
        tags = set(action.tags)
        if not all(tag in tags for tag in filter.tags):
            return False
    if filter.scopes and not has_scopes(action.scopes, filter.scopes):
        return False
    if filter.include is not None and not filter.include(action):
        return False
    return True


class ActionRegistry:
    """An ordered, immutable-by-convention set of actions.

    Visibility is scope-aware, which is what stops an agent from discovering
    tools it could never call.
    """

    def __init__(self, actions: Iterable[Action] = ()) -> None:
        self._actions: dict[str, Action] = {}
        self.add(*list(actions))

    @property
    def size(self) -> int:
        """Number of registered actions."""
        return len(self._actions)

    def __len__(self) -> int:
        return len(self._actions)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._actions

    def add(self, *actions: Action) -> "ActionRegistry":
        """Register actions, rejecting invalid or duplicate names."""
        for action in actions:
            if not isinstance(action, Action):
                raise GapError(
                    "Cannot register a non-action value.",
                    code="INTERNAL",
                    expose=False,
                )
            if not _NAME_PATTERN.fullmatch(action.name):
                raise GapError(
                    f'Invalid action name "{action.name}". Use a dot-namespaced '
                    'name such as "invoices.create".',
                    code="INTERNAL",
                    expose=False,
                )
            if action.name in self._actions:
                raise GapError(
                    f'Action "{action.name}" is already registered.',
                    code="CONFLICT",
                    expose=False,
                )
            if not callable(action.execute):
                raise GapError(
                    f'Action "{action.name}" has no execute function.',
                    code="INTERNAL",
                    expose=False,
                )
            self._actions[action.name] = action
        return self

    def remove(self, name: str) -> bool:
        """Remove an action; returns whether it existed."""
        return self._actions.pop(name, None) is not None

    def clear(self) -> "ActionRegistry":
        """Remove every action, for gateways that refresh a catalog."""
        self._actions.clear()
        return self

    def get(self, name: str) -> Action | None:
        """Return an action or ``None``."""
        return self._actions.get(name)

    def require(self, name: str) -> Action:
        """Return an action or raise ``GapError(NOT_FOUND)``."""
        action = self._actions.get(name)
        if action is None:
            raise GapError(f'Unknown action "{name}".', code="NOT_FOUND")
        return action

    def has(self, name: str) -> bool:
        """Whether an action name is registered."""
        return name in self._actions

    def list(
        self,
        filter: ActionFilter | None = None,
        *,
        names: Sequence[str] | None = None,
        namespace: str | None = None,
        tags: Sequence[str] | None = None,
        scopes: Sequence[str] | None = None,
        include: Callable[[Action], bool] | None = None,
    ) -> list[Action]:
        """List actions in name order, optionally filtered.

        Pass an :class:`ActionFilter`, or the individual fields as keywords:
        ``registry.list(namespace="invoices")``.
        """
        criteria = (names, namespace, tags, scopes, include)
        if filter is not None and any(item is not None for item in criteria):
            raise invalid_input(
                "Pass either filter= or individual list criteria, not both."
            )
        if filter is None and any(item is not None for item in criteria):
            filter = ActionFilter(
                names=names,
                namespace=namespace,
                tags=tags,
                scopes=scopes,
                include=include,
            )
        return sorted(
            (
                action
                for action in self._actions.values()
                if _matches_filter(action, filter)
            ),
            key=lambda action: action.name,
        )

    def visible_to(
        self, scopes: Sequence[str] | None, filter: ActionFilter | None = None
    ) -> list[Action]:
        """Actions a principal with these scopes may discover."""
        return [
            action for action in self.list(filter) if has_scopes(scopes, action.scopes)
        ]

    def namespaces(self) -> list[str]:
        """Sorted first segments of every registered name."""
        return sorted(
            {name.split(".", 1)[0] for name in self._actions if name.split(".", 1)[0]}
        )

    def to_tool_descriptors(
        self,
        *,
        scopes: Sequence[str] | None = None,
        filter: ActionFilter | None = None,
    ) -> list[ToolDescriptor]:
        """JSON-Schema descriptors, scope-filtered when ``scopes`` is given."""
        actions = (
            self.visible_to(scopes, filter) if scopes is not None else self.list(filter)
        )
        return [to_tool_descriptor(action) for action in actions]

    def validate(self) -> list[RegistryIssue]:
        """CI-friendly contract checks.

        Errors should fail a build; warnings are advice. The checks mirror the
        TypeScript registry: names, description length, input shape and field
        documentation, scope format, risky actions without confirmation,
        destructive names, non-idempotent high-risk actions, deprecation and
        incomplete UI bindings.
        """
        issues: list[RegistryIssue] = []
        for action in self.list():
            if not _NAME_PATTERN.fullmatch(action.name):
                issues.append(
                    RegistryIssue(
                        level="error",
                        code="name",
                        action=action.name,
                        message="Invalid tool name.",
                    )
                )

            description = (action.description or "").strip()
            if not description:
                issues.append(
                    RegistryIssue(
                        level="error",
                        code="description.missing",
                        action=action.name,
                        message=(
                            "Every action needs a description written for the model."
                        ),
                    )
                )
            elif len(action.description) < 30:
                issues.append(
                    RegistryIssue(
                        level="warn",
                        code="description.short",
                        action=action.name,
                        message=(
                            "Description is shorter than 30 characters; models "
                            "select tools by description."
                        ),
                    )
                )
            elif len(action.description) > 2000:
                issues.append(
                    RegistryIssue(
                        level="warn",
                        code="description.long",
                        action=action.name,
                        message=(
                            "Description exceeds 2000 characters and spends "
                            "context budget."
                        ),
                    )
                )

            if action.input is not None:
                schema = to_input_json_schema(action.input)
                if not is_object_schema(schema):
                    issues.append(
                        RegistryIssue(
                            level="error",
                            code="input.not_object",
                            action=action.name,
                            message="MCP tool input must be an object schema.",
                        )
                    )
                missing = schema_paths_without_descriptions(schema)
                if missing:
                    issues.append(
                        RegistryIssue(
                            level="warn",
                            code="input.undescribed",
                            action=action.name,
                            message=(
                                "Undescribed input field(s): "
                                + ", ".join(missing[:8])
                                + "."
                            ),
                        )
                    )

            for scope in action.scopes:
                if not _SCOPE_PATTERN.fullmatch(scope):
                    issues.append(
                        RegistryIssue(
                            level="warn",
                            code="scope.format",
                            action=action.name,
                            message=(
                                f'Scope "{scope}" does not follow the '
                                "resource:verb convention."
                            ),
                        )
                    )

            risky = action.risk in {"high", "critical"}
            has_confirmation = action.confirm is True or callable(action.confirm)
            if risky and not has_confirmation:
                issues.append(
                    RegistryIssue(
                        level="warn",
                        code="risk.no_confirmation",
                        action=action.name,
                        message=(
                            f"{action.risk} risk action does not require confirmation."
                        ),
                    )
                )
            if _DESTRUCTIVE_VERBS.search(action.name) and not has_confirmation:
                issues.append(
                    RegistryIssue(
                        level="warn",
                        code="destructive.no_confirmation",
                        action=action.name,
                        message=(
                            "Name looks destructive but the action does not "
                            "require confirmation."
                        ),
                    )
                )
            if risky and not action.idempotent:
                issues.append(
                    RegistryIssue(
                        level="warn",
                        code="risk.not_idempotent",
                        action=action.name,
                        message=(
                            "High-risk action is not idempotent; retries can "
                            "duplicate effects."
                        ),
                    )
                )
            if action.deprecated:
                issues.append(
                    RegistryIssue(
                        level="warn",
                        code="deprecated",
                        action=action.name,
                        message=(
                            action.deprecated
                            if isinstance(action.deprecated, str)
                            else "Action is deprecated."
                        ),
                    )
                )
            if action.ui is not None and not action.ui.route and not action.ui.action:
                issues.append(
                    RegistryIssue(
                        level="warn",
                        code="ui.incomplete",
                        action=action.name,
                        message="UI binding has neither a route nor an action id.",
                    )
                )
        return issues


def to_tool_descriptor(action: Action) -> ToolDescriptor:
    """Convert one action into the MCP-facing descriptor shape."""
    annotations = action.annotations
    title = action.title or (annotations.title if annotations else None) or action.name
    read_only = (
        annotations.read_only_hint
        if annotations and annotations.read_only_hint is not None
        else "read-only" in action.tags
    )
    destructive = (
        annotations.destructive_hint
        if annotations and annotations.destructive_hint is not None
        else action.risk in {"high", "critical"}
    )
    idempotent = (
        annotations.idempotent_hint
        if annotations and annotations.idempotent_hint is not None
        else action.idempotent
    )
    open_world = (
        annotations.open_world_hint
        if annotations and annotations.open_world_hint is not None
        else False
    )

    meta: dict[str, Any] = dict(action.meta)
    meta.update(
        {
            "gap/risk": action.risk,
            "gap/scopes": list(action.scopes),
            "gap/version": action.version,
            "gap/idempotent": action.idempotent,
        }
    )
    if action.tags:
        meta["gap/tags"] = list(action.tags)
    if action.ui is not None:
        meta["gap/ui"] = action.ui.to_dict()
    if action.task:
        meta["gap/task"] = True
    if action.deprecated:
        meta["gap/deprecated"] = action.deprecated

    return ToolDescriptor(
        name=action.name,
        title=title,
        description=action.description,
        input_schema=to_input_json_schema(action.input),
        output_schema=to_output_json_schema(action.output),
        annotations={
            "title": title,
            "readOnlyHint": bool(read_only),
            "destructiveHint": bool(destructive),
            "idempotentHint": bool(idempotent),
            "openWorldHint": bool(open_world),
        },
        meta=meta,
    )


def create_registry(*actions: Action) -> ActionRegistry:
    """Create a registry from action definitions."""
    return ActionRegistry(actions)
