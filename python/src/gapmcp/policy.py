"""Declarative deny / confirm / limits / redaction / dry-run policy."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .action import Action
from .errors import invalid_input
from .types import ActionContext, PolicyDecision, ValidationIssue
from .utils import has_scopes

__all__ = [
    "DEFAULT_AMOUNT_PATHS",
    "GapPolicy",
    "PolicyDocument",
    "PolicyRule",
    "define_policy",
    "parse_policy",
]

DEFAULT_AMOUNT_PATHS: tuple[str, ...] = (
    "amount",
    "total",
    "value",
    "price",
    "cost",
)
"""Keys searched recursively for money-like amounts."""


@dataclass(kw_only=True, slots=True)
class PolicyRule:
    """One rule in a policy document."""

    tools: list[str] | None = None
    scopes: list[str] | None = None
    deny: bool | None = None
    confirm: bool | None = None
    dry_run: bool | None = None
    max_amount: float | None = None
    amount_paths: list[str] | None = None
    max_array_length: int | None = None
    array_paths: list[str] | None = None
    redact: list[str] | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if self.tools is not None:
            payload["tools"] = list(self.tools)
        if self.scopes is not None:
            payload["scopes"] = list(self.scopes)
        if self.deny is not None:
            payload["deny"] = self.deny
        if self.confirm is not None:
            payload["confirm"] = self.confirm
        if self.dry_run is not None:
            payload["dryRun"] = self.dry_run
        if self.max_amount is not None:
            payload["maxAmount"] = self.max_amount
        if self.amount_paths is not None:
            payload["amountPaths"] = list(self.amount_paths)
        if self.max_array_length is not None:
            payload["maxArrayLength"] = self.max_array_length
        if self.array_paths is not None:
            payload["arrayPaths"] = list(self.array_paths)
        if self.redact is not None:
            payload["redact"] = list(self.redact)
        if self.reason is not None:
            payload["reason"] = self.reason
        return payload


@dataclass(kw_only=True, slots=True)
class PolicyDocument:
    """A complete, versioned policy document."""

    version: int = 1
    rules: list[PolicyRule] = field(default_factory=list)
    default: str = "allow"
    redact: list[str] | None = None
    confirm: list[str] | None = None
    deny: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "version": self.version,
            "default": self.default,
            "rules": [rule.to_dict() for rule in self.rules],
        }
        if self.redact is not None:
            payload["redact"] = list(self.redact)
        if self.confirm is not None:
            payload["confirm"] = list(self.confirm)
        if self.deny is not None:
            payload["deny"] = list(self.deny)
        return payload


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _issue(issues: list[ValidationIssue], path: str, message: str, code: str) -> None:
    issues.append(ValidationIssue(path=path, message=message, code=code))


def _validate_string_array(
    value: Any, path: str, issues: list[ValidationIssue]
) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        _issue(
            issues,
            path,
            "Expected an array of non-empty strings.",
            "invalid_type",
        )
        return
    for index, entry in enumerate(value):
        if not isinstance(entry, str) or not entry.strip():
            _issue(
                issues,
                f"{path}[{index}]",
                "Expected a non-empty string.",
                "invalid_value",
            )


def _validate_rule(raw: Any, path: str, issues: list[ValidationIssue]) -> None:
    if not _is_mapping(raw):
        _issue(issues, path, "Expected a policy rule object.", "invalid_type")
        return
    for key in ("tools", "scopes", "amountPaths", "arrayPaths", "redact"):
        _validate_string_array(raw.get(key), f"{path}.{key}", issues)
    for key in ("deny", "confirm", "dryRun"):
        if key in raw and raw[key] is not None and not isinstance(raw[key], bool):
            _issue(issues, f"{path}.{key}", "Expected a boolean.", "invalid_type")
    if "maxAmount" in raw and raw["maxAmount"] is not None:
        value = raw["maxAmount"]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            _issue(
                issues,
                f"{path}.maxAmount",
                "Expected a finite, non-negative number.",
                "invalid_value",
            )
    if "maxArrayLength" in raw and raw["maxArrayLength"] is not None:
        value = raw["maxArrayLength"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _issue(
                issues,
                f"{path}.maxArrayLength",
                "Expected a non-negative integer.",
                "invalid_value",
            )
    if (
        "reason" in raw
        and raw["reason"] is not None
        and not isinstance(raw["reason"], str)
    ):
        _issue(issues, f"{path}.reason", "Expected a string.", "invalid_type")


def _strings(raw: Mapping[str, Any], key: str) -> list[str] | None:
    value = raw.get(key)
    return list(value) if isinstance(value, list) else None


def _normalize_rule(raw: Mapping[str, Any]) -> PolicyRule:
    return PolicyRule(
        tools=_strings(raw, "tools"),
        scopes=_strings(raw, "scopes"),
        deny=raw.get("deny") if isinstance(raw.get("deny"), bool) else None,
        confirm=raw.get("confirm") if isinstance(raw.get("confirm"), bool) else None,
        dry_run=raw.get("dryRun") if isinstance(raw.get("dryRun"), bool) else None,
        max_amount=float(raw["maxAmount"])
        if isinstance(raw.get("maxAmount"), (int, float))
        and not isinstance(raw.get("maxAmount"), bool)
        else None,
        amount_paths=_strings(raw, "amountPaths"),
        max_array_length=raw.get("maxArrayLength")
        if isinstance(raw.get("maxArrayLength"), int)
        and not isinstance(raw.get("maxArrayLength"), bool)
        else None,
        array_paths=_strings(raw, "arrayPaths"),
        redact=_strings(raw, "redact"),
        reason=raw.get("reason") if isinstance(raw.get("reason"), str) else None,
    )


def _normalize_policy(value: Any) -> PolicyDocument:
    if not _is_mapping(value):
        raise invalid_input(
            "Invalid policy document.",
            {
                "issues": [
                    {
                        "path": "(root)",
                        "message": "Policy must be an object.",
                        "code": "invalid_type",
                    }
                ]
            },
        )

    issues: list[ValidationIssue] = []
    version = value.get("version")
    if version is None:
        _issue(
            issues,
            "version",
            "Policy version is required; expected 1.",
            "required",
        )
    elif isinstance(version, bool) or not isinstance(version, int) or version != 1:
        _issue(
            issues,
            "version",
            f"Unsupported policy version {version!r}; expected 1.",
            "invalid_value",
        )

    default = value.get("default")
    if default is not None and default not in {"allow", "deny"}:
        _issue(
            issues,
            "default",
            'Expected "allow" or "deny".',
            "invalid_value",
        )

    _validate_string_array(value.get("redact"), "redact", issues)
    _validate_string_array(value.get("confirm"), "confirm", issues)
    _validate_string_array(value.get("deny"), "deny", issues)

    rules = value.get("rules")
    if not isinstance(rules, list):
        _issue(
            issues,
            "rules",
            (
                "Policy rules are required."
                if rules is None
                else "Expected an array of rules."
            ),
            "required" if rules is None else "invalid_type",
        )
    else:
        for index, rule in enumerate(rules):
            _validate_rule(rule, f"rules[{index}]", issues)

    if issues:
        raise invalid_input(
            "Invalid policy document.",
            {"issues": [issue.to_dict() for issue in issues]},
        )

    raw_rules = [rule for rule in rules if isinstance(rule, Mapping)]
    document = PolicyDocument(
        version=1,
        rules=[_normalize_rule(rule) for rule in raw_rules],
        default=default if default in {"allow", "deny"} else "allow",
        redact=_strings(value, "redact"),
        confirm=_strings(value, "confirm"),
        deny=_strings(value, "deny"),
    )
    return document


def define_policy(
    document: Mapping[str, Any] | PolicyDocument,
) -> PolicyDocument:
    """Validate a policy at definition time and return its normalized form."""
    if isinstance(document, PolicyDocument):
        document = document.to_dict()
    return _normalize_policy(document)


def parse_policy(
    input: str | Mapping[str, Any] | PolicyDocument,
) -> PolicyDocument:
    """Parse and validate a policy from JSON text, a mapping or a document.

    Raises ``GapError(INVALID_INPUT)`` with an ``issues`` array when the
    document is malformed.
    """
    if isinstance(input, PolicyDocument):
        return _normalize_policy(input.to_dict())
    if isinstance(input, str):
        try:
            parsed = json.loads(input)
        except json.JSONDecodeError as error:
            raise invalid_input(
                "Policy must be valid JSON.",
                {
                    "issues": [
                        {
                            "path": "(root)",
                            "message": "Invalid JSON.",
                            "code": "invalid_json",
                        }
                    ]
                },
            ) from error
        return _normalize_policy(parsed)
    return _normalize_policy(input)


def _matches_tool(pattern: str, name: str) -> bool:
    if pattern == "*" or pattern == name:
        return True
    if pattern.endswith(".*"):
        return name.startswith(pattern[:-1])
    return False


def _matches_any(patterns: Sequence[str] | None, name: str) -> bool:
    return any(_matches_tool(pattern, name) for pattern in (patterns or ()))


def _rule_matches(rule: PolicyRule, action_name: str, scopes: Sequence[str]) -> bool:
    if not has_scopes(scopes, rule.scopes):
        return False
    if rule.tools is None:
        return True
    return any(_matches_tool(pattern, action_name) for pattern in rule.tools)


def _merge_paths(*groups: Sequence[str] | None) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for group in groups:
        for path in group or ():
            if path not in seen:
                seen.add(path)
                result.append(path)
    return result


def _is_simple_path(path: str) -> bool:
    return "." not in path and "[" not in path


def _path_segments(path: str) -> list[str]:
    expanded = path
    for token in ("[]", "[*]"):
        expanded = expanded.replace(token, ".*")
    import re

    expanded = re.sub(r"\[(\d+)\]", r".\1", expanded)
    return [part.strip() for part in expanded.split(".") if part.strip()]


def _resolve_path_values(value: Any, path: str) -> list[Any]:
    current: list[Any] = [value]
    for segment in _path_segments(path):
        next_values: list[Any] = []
        for node in current:
            if node is None:
                continue
            if isinstance(node, list):
                if segment == "*":
                    next_values.extend(node)
                    continue
                try:
                    index = int(segment)
                except ValueError:
                    continue
                if 0 <= index < len(node):
                    next_values.append(node[index])
                continue
            if isinstance(node, Mapping):
                if segment == "*":
                    next_values.extend(node.values())
                else:
                    next_values.append(node.get(segment))
        current = [entry for entry in next_values if entry is not None]
    return current


@dataclass(kw_only=True, slots=True)
class _LimitViolation:
    path: str
    value: float


def _find_amount_violation(
    value: Any, paths: Sequence[str], max_amount: float
) -> _LimitViolation | None:
    simple = {path for path in paths if _is_simple_path(path)}
    complex_paths = [path for path in paths if not _is_simple_path(path)]

    if simple:
        seen: set[int] = set()

        def visit(node: Any, path: str) -> _LimitViolation | None:
            if isinstance(node, list):
                identity = id(node)
                if identity in seen:
                    return None
                seen.add(identity)
                for index, item in enumerate(node):
                    violation = visit(item, f"{path}[{index}]")
                    if violation is not None:
                        return violation
                return None
            if not isinstance(node, Mapping):
                return None
            identity = id(node)
            if identity in seen:
                return None
            seen.add(identity)
            for key, child in node.items():
                child_path = f"{path}.{key}" if path else str(key)
                if (
                    key in simple
                    and isinstance(child, (int, float))
                    and not isinstance(child, bool)
                    and math.isfinite(child)
                    and child > max_amount
                ):
                    return _LimitViolation(path=child_path, value=float(child))
                violation = visit(child, child_path)
                if violation is not None:
                    return violation
            return None

        found = visit(value, "")
        if found is not None:
            return found

    for path in complex_paths:
        for candidate in _resolve_path_values(value, path):
            if (
                isinstance(candidate, (int, float))
                and not isinstance(candidate, bool)
                and math.isfinite(candidate)
                and candidate > max_amount
            ):
                return _LimitViolation(path=path, value=float(candidate))
    return None


def _find_array_violation(
    value: Any,
    paths: Sequence[str] | None,
    max_length: int,
) -> _LimitViolation | None:
    if paths is not None:
        for path in paths:
            for candidate in _resolve_path_values(value, path):
                if isinstance(candidate, list) and len(candidate) > max_length:
                    return _LimitViolation(path=path, value=float(len(candidate)))
        return None

    seen: set[int] = set()

    def visit(node: Any, path: str) -> _LimitViolation | None:
        if isinstance(node, list):
            identity = id(node)
            if identity in seen:
                return None
            seen.add(identity)
            if len(node) > max_length:
                return _LimitViolation(path=path or "(root)", value=float(len(node)))
            for index, item in enumerate(node):
                violation = visit(item, f"{path}[{index}]")
                if violation is not None:
                    return violation
            return None
        if not isinstance(node, Mapping):
            return None
        identity = id(node)
        if identity in seen:
            return None
        seen.add(identity)
        for key, child in node.items():
            violation = visit(child, f"{path}.{key}" if path else str(key))
            if violation is not None:
                return violation
        return None

    return visit(value, "")


class GapPolicy:
    """A policy engine backed by a validated :class:`PolicyDocument`.

    Evaluation is deterministic:

    1. document-level ``deny`` globs
    2. the first matching rule deny (including limit violations)
    3. confirmations from the document or any matching rule
    4. the document default, where a ``"deny"`` default needs an explicit
       non-denying, non-confirming matching rule to allow the call

    Normal denials are returned as decisions, never thrown.
    """

    def __init__(self, document: Mapping[str, Any] | PolicyDocument | str) -> None:
        self.document: PolicyDocument = parse_policy(document)

    def evaluate(self, action: Action, args: Any, ctx: ActionContext) -> PolicyDecision:
        """Evaluate one action invocation against the policy."""
        action_name = action.name
        scopes = list(
            ctx.scopes if ctx.scopes is not None else ctx.principal.scopes or []
        )
        matching = [
            rule
            for rule in self.document.rules
            if _rule_matches(rule, action_name, scopes)
        ]

        if _matches_any(self.document.deny, action_name):
            return PolicyDecision(
                decision="deny",
                code="POLICY_DENIED",
                reason="Denied by the policy document.",
            )

        confirm_reason: str | None = None
        confirm_matched = False

        for rule in matching:
            if rule.deny is True:
                return PolicyDecision(
                    decision="deny",
                    code="POLICY_DENIED",
                    reason=rule.reason or "Denied by policy.",
                )

            if rule.max_amount is not None:
                violation = _find_amount_violation(
                    args,
                    rule.amount_paths
                    if rule.amount_paths is not None
                    else DEFAULT_AMOUNT_PATHS,
                    rule.max_amount,
                )
                if violation is not None:
                    reason = rule.reason or (
                        f'Amount {violation.value:g} at "{violation.path}" '
                        f"exceeds the max amount of {rule.max_amount:g}."
                    )
                    return PolicyDecision(
                        decision="deny",
                        code="LIMIT_EXCEEDED",
                        reason=reason,
                        metadata={
                            "limit": rule.max_amount,
                            "path": violation.path,
                            "value": violation.value,
                        },
                    )

            if rule.max_array_length is not None:
                violation = _find_array_violation(
                    args, rule.array_paths, rule.max_array_length
                )
                if violation is not None:
                    reason = rule.reason or (
                        f'Array at "{violation.path}" has '
                        f"{int(violation.value)} items, exceeding the max "
                        f"length of {rule.max_array_length}."
                    )
                    return PolicyDecision(
                        decision="deny",
                        code="LIMIT_EXCEEDED",
                        reason=reason,
                        metadata={
                            "limit": rule.max_array_length,
                            "path": violation.path,
                            "value": violation.value,
                        },
                    )

            if rule.confirm is True and not confirm_matched:
                confirm_matched = True
                confirm_reason = rule.reason or "Confirmation required by policy."

        document_confirm = _matches_any(self.document.confirm, action_name)
        redact_paths = _merge_paths(
            self.document.redact,
            *(rule.redact for rule in matching),
        )
        dry_run = any(rule.dry_run is True for rule in matching)
        allow_rule = next(
            (
                rule
                for rule in matching
                if rule.deny is not True and rule.confirm is not True
            ),
            None,
        )

        if confirm_matched or document_confirm:
            if dry_run:
                ctx.dry_run = True
            return PolicyDecision(
                decision="confirm",
                reason=(
                    confirm_reason or "Confirmation required by the policy document."
                ),
                redact_paths=redact_paths or None,
                metadata={"dryRun": True} if dry_run else None,
            )

        if self.document.default == "deny" and allow_rule is None:
            return PolicyDecision(
                decision="deny",
                code="POLICY_DENIED",
                reason="Denied by default policy.",
            )

        if dry_run:
            ctx.dry_run = True

        return PolicyDecision(
            decision="allow",
            reason=allow_rule.reason if allow_rule and allow_rule.reason else None,
            redact_paths=redact_paths or None,
            metadata={"dryRun": True} if dry_run else None,
        )
