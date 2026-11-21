"""Policy matching, limits, redaction, dry-run and validation."""

from __future__ import annotations

import pytest

from gapmcp import (
    GapError,
    GapPolicy,
    Principal,
    define_action,
    define_policy,
    parse_policy,
)
from gapmcp.testing import test_context as make_context


def action(name: str):
    return define_action(
        lambda input, ctx: input,
        name=name,
        description=f"Perform the {name} operation for a customer account.",
    )


def test_define_policy_normalizes_and_parses_json() -> None:
    document = define_policy(
        {
            "version": 1,
            "default": "deny",
            "redact": ["secret"],
            "rules": [
                {
                    "tools": ["invoices.*"],
                    "maxAmount": 100,
                    "amountPaths": ["order.total"],
                    "maxArrayLength": 2,
                    "arrayPaths": ["items"],
                    "redact": ["card.number"],
                    "reason": "Small invoices only.",
                }
            ],
        }
    )
    assert document.default == "deny"
    assert document.rules[0].max_amount == 100.0
    assert "dryRun" not in document.rules[0].to_dict()

    parsed = parse_policy(document.to_dict())
    assert parsed.to_dict() == document.to_dict()


def test_invalid_policy_documents_raise_with_issues() -> None:
    with pytest.raises(GapError) as missing:
        define_policy({"version": 1})
    assert missing.value.code == "INVALID_INPUT"
    assert any(issue["code"] == "required" for issue in missing.value.details["issues"])

    with pytest.raises(GapError) as version:
        define_policy({"version": 2, "rules": []})
    assert version.value.code == "INVALID_INPUT"

    with pytest.raises(GapError):
        parse_policy("{not json")

    with pytest.raises(GapError):
        define_policy(
            {
                "version": 1,
                "rules": [{"tools": "invoices.*"}],
            }
        )

    with pytest.raises(GapError):
        define_policy(
            {
                "version": 1,
                "rules": [{"maxAmount": -1}],
            }
        )


def test_default_allow_and_exact_deny() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [
                    {"tools": ["invoices.delete"], "deny": True, "reason": "Nope."}
                ],
            }
        )
    )
    ctx = make_context()
    allowed = policy.evaluate(action("invoices.create"), {}, ctx)
    assert allowed.decision == "allow"
    denied = policy.evaluate(action("invoices.delete"), {}, ctx)
    assert denied.decision == "deny"
    assert denied.code == "POLICY_DENIED"
    assert denied.reason == "Nope."


def test_glob_namespace_and_document_deny() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "deny": ["admin.*"],
                "rules": [{"tools": ["invoices.*"], "confirm": True}],
            }
        )
    )
    ctx = make_context()
    assert policy.evaluate(action("admin.drop"), {}, ctx).decision == "deny"
    assert policy.evaluate(action("users.get"), {}, ctx).decision == "allow"
    assert policy.evaluate(action("invoices.send"), {}, ctx).decision == "confirm"


def test_document_confirm_and_default_deny_needs_matching_rule() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "default": "deny",
                "confirm": ["invoices.send"],
                "rules": [
                    {"tools": ["invoices.get"], "reason": "Read-only access."},
                    {"tools": ["invoices.send"], "confirm": True},
                ],
            }
        )
    )
    ctx = make_context()
    assert policy.evaluate(action("invoices.get"), {}, ctx).decision == "allow"
    confirm = policy.evaluate(action("invoices.send"), {}, ctx)
    assert confirm.decision == "confirm"
    assert confirm.reason == "Confirmation required by policy."
    assert policy.evaluate(action("users.get"), {}, ctx).decision == "deny"


def test_amount_limits_default_paths_and_nested_values() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [{"tools": ["invoices.*"], "maxAmount": 500}],
            }
        )
    )
    ctx = make_context()
    assert (
        policy.evaluate(action("invoices.create"), {"amount": 500}, ctx).decision
        == "allow"
    )

    denied = policy.evaluate(
        action("invoices.create"),
        {"order": {"lines": [{"total": 900}]}},
        ctx,
    )
    assert denied.decision == "deny"
    assert denied.code == "LIMIT_EXCEEDED"
    assert denied.metadata is not None
    assert denied.metadata["value"] == 900

    assert (
        policy.evaluate(action("users.update"), {"amount": 9_000}, ctx).decision
        == "allow"
    )


def test_amount_limit_respects_explicit_paths() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [
                    {
                        "tools": ["invoices.*"],
                        "maxAmount": 100,
                        "amountPaths": ["payment.amount"],
                    }
                ],
            }
        )
    )
    ctx = make_context()
    assert (
        policy.evaluate(action("invoices.create"), {"amount": 1_000}, ctx).decision
        == "allow"
    )
    denied = policy.evaluate(
        action("invoices.create"), {"payment": {"amount": 101}}, ctx
    )
    assert denied.decision == "deny"
    assert denied.code == "LIMIT_EXCEEDED"


def test_array_limits_default_any_array_and_explicit_paths() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [
                    {"tools": ["bulk.*"], "maxArrayLength": 3},
                ],
            }
        )
    )
    ctx = make_context()
    assert (
        policy.evaluate(action("bulk.send"), {"items": [1, 2, 3]}, ctx).decision
        == "allow"
    )
    denied = policy.evaluate(action("bulk.send"), {"items": [1, 2, 3, 4]}, ctx)
    assert denied.decision == "deny"
    assert denied.code == "LIMIT_EXCEEDED"

    scoped = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [
                    {
                        "tools": ["bulk.*"],
                        "maxArrayLength": 1,
                        "arrayPaths": ["items"],
                    }
                ],
            }
        )
    )
    assert (
        scoped.evaluate(
            action("bulk.send"), {"items": [1], "other": [1, 2, 3]}, ctx
        ).decision
        == "allow"
    )


def test_confirm_and_dry_run_set_context() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [
                    {
                        "tools": ["invoices.refund"],
                        "confirm": True,
                        "dryRun": True,
                        "reason": "Finance approval.",
                    }
                ],
            }
        )
    )
    ctx = make_context()
    decision = policy.evaluate(action("invoices.refund"), {}, ctx)
    assert decision.decision == "confirm"
    assert decision.reason == "Finance approval."
    assert decision.metadata == {"dryRun": True}
    assert ctx.dry_run is True


def test_redactions_merge_across_matching_rules() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "redact": ["password"],
                "rules": [
                    {"tools": ["invoices.*"], "redact": ["card.number"]},
                    {"tools": ["invoices.pay"], "redact": ["card.cvv"]},
                ],
            }
        )
    )
    ctx = make_context()
    decision = policy.evaluate(action("invoices.pay"), {}, ctx)
    assert decision.redact_paths == ["password", "card.number", "card.cvv"]


def test_scope_gated_rules_only_apply_to_matching_principals() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [
                    {
                        "tools": ["invoices.*"],
                        "scopes": ["finance"],
                        "maxAmount": 10,
                    }
                ],
            }
        )
    )
    finance = make_context(
        principal=Principal(id="fin", scopes=["finance", "invoices:read"])
    )
    engineering = make_context(principal=Principal(id="eng", scopes=["invoices:read"]))
    assert (
        policy.evaluate(action("invoices.create"), {"amount": 100}, finance).decision
        == "deny"
    )
    assert (
        policy.evaluate(
            action("invoices.create"), {"amount": 100}, engineering
        ).decision
        == "allow"
    )


def test_first_deny_wins_even_when_later_rules_allow() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [
                    {"tools": ["invoices.*"], "deny": True, "reason": "First."},
                    {"tools": ["invoices.create"], "reason": "Second."},
                ],
            }
        )
    )
    decision = policy.evaluate(action("invoices.create"), {}, make_context())
    assert decision.decision == "deny"
    assert decision.reason == "First."
