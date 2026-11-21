"""Registry behavior, visibility and contract checks."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, Field

from gapmcp import (
    ActionRegistry,
    GapError,
    create_registry,
    define_action,
    to_tool_descriptor,
)


class InvoiceInput(BaseModel):
    amount: float = Field(description="Invoice total in USD.")


def make_action(name: str, *, scopes=None, **kwargs):
    return define_action(
        lambda input, ctx: input,
        name=name,
        description=kwargs.pop(
            "description",
            f"Perform the {name} operation for a customer account.",
        ),
        scopes=scopes,
        **kwargs,
    )


def test_add_duplicate_and_name_validation() -> None:
    action = make_action("invoices.create")
    registry = create_registry(action)
    assert len(registry) == 1
    assert "invoices.create" in registry
    assert registry.has("invoices.create")

    with pytest.raises(GapError) as duplicate:
        registry.add(make_action("invoices.create"))
    assert duplicate.value.code == "CONFLICT"

    with pytest.raises(GapError):
        registry.add(make_action("123bad"))


def test_get_require_remove_and_namespaces() -> None:
    registry = create_registry(make_action("invoices.create"), make_action("users.get"))
    assert registry.get("users.get") is not None
    assert registry.get("missing") is None
    with pytest.raises(GapError) as missing:
        registry.require("missing")
    assert missing.value.code == "NOT_FOUND"
    assert registry.namespaces() == ["invoices", "users"]
    assert registry.remove("users.get") is True
    assert registry.remove("users.get") is False
    assert registry.size == 1
    registry.clear()
    assert registry.size == 0


def test_list_sorted_and_filters() -> None:
    registry = create_registry(
        make_action("users.get", tags=["read"]),
        make_action("invoices.create", tags=["write", "finance"]),
        make_action("invoices.list", tags=["read", "finance"]),
    )
    assert [action.name for action in registry.list()] == [
        "invoices.create",
        "invoices.list",
        "users.get",
    ]
    assert [action.name for action in registry.list(namespace="invoices")] == [
        "invoices.create",
        "invoices.list",
    ]
    assert [action.name for action in registry.list(tags=["read", "finance"])] == [
        "invoices.list"
    ]
    assert [
        action.name for action in registry.list(names=["users.get", "invoices.list"])
    ] == ["invoices.list", "users.get"]


def test_visible_to_filters_by_scope() -> None:
    registry = create_registry(
        make_action("public.get"),
        make_action("invoices.create", scopes=["invoices:write"]),
        make_action("invoices.read", scopes=["invoices:read"]),
    )
    assert [action.name for action in registry.visible_to(["*"])] == [
        "invoices.create",
        "invoices.read",
        "public.get",
    ]
    assert [action.name for action in registry.visible_to(["invoices:read"])] == [
        "invoices.read",
        "public.get",
    ]
    assert [action.name for action in registry.visible_to([])] == ["public.get"]
    assert [action.name for action in registry.visible_to(["invoices:*"])] == [
        "invoices.create",
        "invoices.read",
        "public.get",
    ]


def test_tool_descriptor_from_pydantic_and_plain_schema() -> None:
    pydantic_action = make_action(
        "invoices.create",
        description="Create a draft invoice for a customer and return its id.",
        input=InvoiceInput,
        output=InvoiceInput,
        scopes=["invoices:write"],
        risk="medium",
        idempotent=True,
        tags=["read-only"],
        ui=None,
    )
    descriptor = to_tool_descriptor(pydantic_action)
    assert descriptor.name == "invoices.create"
    assert descriptor.input_schema["type"] == "object"
    assert "amount" in descriptor.input_schema["properties"]
    assert descriptor.output_schema is not None
    assert descriptor.annotations is not None
    assert descriptor.annotations["readOnlyHint"] is True
    assert descriptor.meta is not None
    assert descriptor.meta["gap/risk"] == "medium"

    plain_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"id": {"type": "string", "description": "Record id."}},
        "required": ["id"],
    }
    plain_action = make_action(
        "invoices.get",
        description="Fetch a single invoice by its opaque record id.",
        input=plain_schema,
        output={"type": "object", "properties": {"id": {"type": "string"}}},
    )
    plain_descriptor = to_tool_descriptor(plain_action)
    assert "$schema" not in plain_descriptor.input_schema
    assert plain_descriptor.input_schema["properties"]["id"]["description"]
    assert plain_descriptor.output_schema == {
        "type": "object",
        "properties": {"id": {"type": "string"}},
    }


def test_tool_descriptor_for_schemaless_action() -> None:
    action = make_action("demo.ping")
    descriptor = to_tool_descriptor(action)
    assert descriptor.input_schema == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
    assert descriptor.output_schema is None
    assert descriptor.annotations["readOnlyHint"] is False


def test_reserved_meta_keys_cannot_be_spoofed() -> None:
    action = make_action(
        "invoices.delete",
        risk="critical",
        meta={"gap/risk": "low", "gap/scopes": []},
    )
    descriptor = to_tool_descriptor(action)
    assert descriptor.meta["gap/risk"] == "critical"
    assert descriptor.meta["gap/scopes"] == []


def test_validate_reports_errors_and_warnings() -> None:
    registry = create_registry(
        make_action("short.desc", description="Too short."),
        make_action(
            "invoices.delete",
            description="Delete an invoice record permanently from the service.",
            risk="critical",
        ),
        make_action(
            "demo.bad_schema",
            description="An action whose input schema is not object shaped.",
            input={"type": "array", "items": {"type": "string"}},
        ),
    )
    issues = registry.validate()
    codes = {issue.code for issue in issues}
    assert "description.short" in codes
    assert "risk.no_confirmation" in codes
    assert "risk.not_idempotent" in codes
    assert "destructive.no_confirmation" in codes
    assert "input.not_object" in codes


def test_validate_clean_action_has_no_issues() -> None:
    action = define_action(
        lambda input, ctx: input,
        name="invoices.create",
        description="Create a draft invoice for a customer and return its id.",
        input=InvoiceInput,
        risk="low",
        idempotent=True,
        tags=["read-only"],
    )
    assert ActionRegistry([action]).validate() == []
