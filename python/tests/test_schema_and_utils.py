"""Schema conversion, validation, hashing and redaction."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from decimal import Decimal

import pytest
from pydantic import BaseModel, Field

from gapmcp import (
    GapError,
    canonical_json,
    deep_get,
    has_scopes,
    hash_value,
    missing_scopes,
    parse_value,
    redact,
    schema_paths_without_descriptions,
    to_input_json_schema,
    to_output_json_schema,
    validate_value,
)


class Profile(BaseModel):
    email: str = Field(min_length=1, description="Account email address.")
    age: int | None = Field(default=None, description="Age in years.")


class Wrapper(BaseModel):
    profile: Profile = Field(description="Nested profile object.")


def test_pydantic_input_and_output_schemas() -> None:
    input_schema = to_input_json_schema(Profile)
    assert input_schema["type"] == "object"
    assert input_schema["properties"]["email"]["description"]
    assert "$defs" not in input_schema or isinstance(input_schema["$defs"], dict)

    output_schema = to_output_json_schema(Profile)
    assert output_schema is not None
    assert output_schema["type"] == "object"


def test_plain_schema_passthrough_copies_and_strips_ids() -> None:
    source = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:test",
        "type": "object",
        "properties": {"value": {"type": "string", "description": "A value."}},
    }
    schema = to_input_json_schema(source)
    assert "$schema" not in schema and "$id" not in schema
    schema["properties"]["value"]["type"] = "integer"
    assert source["properties"]["value"]["type"] == "string"


def test_object_default_when_no_input_schema() -> None:
    assert to_input_json_schema(None)["type"] == "object"
    assert to_output_json_schema(None) is None


def test_validate_pydantic_success_and_issues() -> None:
    success = validate_value(Profile, {"email": "a@example.com"})
    assert success.success is True
    assert isinstance(success.data, Profile)

    failure = validate_value(Profile, {"email": 42, "unknown": True})
    assert failure.success is False
    assert any(issue.path == "email" for issue in failure.issues)


def test_parse_value_raises_structured_error() -> None:
    with pytest.raises(GapError) as error:
        parse_value(Profile, {"email": ""}, "input")
    assert error.value.code == "INVALID_INPUT"
    assert error.value.details["issues"][0]["path"] == "email"


def test_json_schema_validation_and_nested_descriptions() -> None:
    schema = {
        "type": "object",
        "properties": {
            "profile": {
                "type": "object",
                "properties": {
                    "email": {"type": "string"},
                    "tags": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"name": {"type": "string"}},
                        },
                    },
                },
            },
            "note": {"description": "Documented leaf."},
        },
        "required": ["profile"],
    }
    failure = validate_value(schema, {"profile": {"email": 1}})
    assert failure.success is False
    assert any("profile.email" in issue.path for issue in failure.issues)

    missing = schema_paths_without_descriptions(schema)
    assert "profile" in missing
    assert "profile.email" in missing
    assert "profile.tags[].name" in missing


def test_validate_none_schema_accepts_anything() -> None:
    result = validate_value(None, {"anything": [1, 2, 3]})
    assert result.success is True
    assert result.data == {"anything": [1, 2, 3]}


def test_canonical_json_is_deterministic_and_js_compatible() -> None:
    left = {"b": 1.0, "a": [2, {"c": None}]}
    right = {"a": [2, {"c": None}], "b": 1}
    assert canonical_json(left) == canonical_json(right) == '{"a":[2,{"c":null}],"b":1}'
    assert hash_value(left) == hash_value(right)
    assert len(hash_value(left)) == 64

    moment = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert canonical_json({"at": moment}) == '{"at":"2025-01-02T03:04:05.000Z"}'
    assert canonical_json({"n": Decimal("2.0")}) == '{"n":2}'
    assert canonical_json({"n": math.inf}) == '{"n":null}'


def test_canonical_json_rejects_circular_values() -> None:
    value: dict[str, object] = {}
    value["self"] = value
    with pytest.raises(TypeError):
        canonical_json(value)


def test_scope_matching() -> None:
    assert has_scopes(["*"], ["anything"])
    assert has_scopes(["invoices:*"], ["invoices:read", "invoices:write"])
    assert not has_scopes(["invoices:read"], ["invoices:write"])
    assert has_scopes(None, [])
    assert missing_scopes(["invoices:read"], ["invoices:read", "users:read"]) == [
        "users:read"
    ]


def test_redaction_wildcards_and_original_untouched() -> None:
    source = {
        "email": "a@example.com",
        "cards": [{"number": "4111", "cvv": "123"}],
        "items": [{"ssn": "1"}, {"ssn": "2"}],
    }
    redacted = redact(source, ["email", "cards[].number", "items[*].ssn"])
    assert redacted["email"] == "[REDACTED]"
    assert redacted["cards"][0]["number"] == "[REDACTED]"
    assert redacted["cards"][0]["cvv"] == "123"
    assert [item["ssn"] for item in redacted["items"]] == ["[REDACTED]", "[REDACTED]"]
    assert source["email"] == "a@example.com"


def test_redact_missing_path_is_a_noop_and_deep_get() -> None:
    value = {"a": {"b": [10, 20]}}
    assert redact(value, ["missing.path", "a.b[5]"]) == value
    assert deep_get(value, "a.b[1]") == 20
    assert deep_get(value, "a.b[9]") is None
    assert deep_get(value, "a.nope") is None
