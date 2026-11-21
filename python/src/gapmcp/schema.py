"""Conversion and validation for pydantic models and plain JSON Schema."""

from __future__ import annotations

import copy
from typing import Any, Mapping, TypeVar

from pydantic import BaseModel, ValidationError
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .errors import GapError, invalid_input
from .types import JsonSchema, ValidationIssue, ValidationResult

T = TypeVar("T")

SchemaLike = type[BaseModel] | Mapping[str, Any]
"""Either a pydantic model class or a plain JSON Schema object."""

__all__ = [
    "SchemaLike",
    "is_json_schema",
    "is_object_schema",
    "is_pydantic_model",
    "parse_value",
    "schema_paths_without_descriptions",
    "to_input_json_schema",
    "to_json_schema",
    "to_output_json_schema",
    "validate_value",
]


def is_pydantic_model(value: Any) -> bool:
    """True for a pydantic ``BaseModel`` subclass (not an instance)."""
    return isinstance(value, type) and issubclass(value, BaseModel)


def is_json_schema(value: Any) -> bool:
    """True for a mapping that can act as a JSON Schema."""
    return isinstance(value, Mapping)


def _clean_schema(schema: Mapping[str, Any]) -> JsonSchema:
    # MCP tool schemas are embedded in a larger document; a nested `$schema`
    # or `$id` confuses some clients.
    return {
        str(key): copy.deepcopy(item)
        for key, item in schema.items()
        if key not in {"$schema", "$id"}
    }


def to_json_schema(
    schema: SchemaLike | None, *, mode: str = "input"
) -> JsonSchema | None:
    """Convert either schema representation to JSON Schema.

    Pydantic models are generated with ``mode="validation"`` for input (what
    the action receives) and ``mode="serialization"`` for output (what the
    action returns). Plain dict schemas are copied and passed through.
    """
    if schema is None:
        return None
    if is_pydantic_model(schema):
        try:
            generated = schema.model_json_schema(
                mode="validation" if mode == "input" else "serialization",
                by_alias=True,
            )
        except Exception as error:  # pragma: no cover - pydantic edge cases
            raise GapError(
                "Failed to convert a pydantic schema to JSON Schema.",
                code="INTERNAL",
                expose=False,
                cause=error,
            ) from error
        return _clean_schema(generated)
    if not isinstance(schema, Mapping):
        raise GapError(
            "A schema must be a pydantic model class or a JSON Schema object.",
            code="INTERNAL",
            expose=False,
        )
    return _clean_schema(schema)


def to_input_json_schema(schema: SchemaLike | None) -> JsonSchema:
    """JSON Schema for a tool input, always object-shaped when possible."""
    converted = to_json_schema(schema, mode="input")
    if converted is None:
        return {"type": "object", "properties": {}, "additionalProperties": False}
    if converted.get("type") is None:
        return {**converted, "type": "object"}
    return converted


def to_output_json_schema(schema: SchemaLike | None) -> JsonSchema | None:
    """JSON Schema for a tool output, or ``None`` when no output is declared."""
    return to_json_schema(schema, mode="output")


def _pydantic_issues(error: ValidationError) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for entry in error.errors():
        location = [str(part) for part in entry.get("loc", ())]
        issues.append(
            ValidationIssue(
                path=".".join(location) if location else "(root)",
                message=str(entry.get("msg", "Invalid value.")),
                code=str(entry.get("type", "invalid")),
            )
        )
    return issues


def _json_schema_issues(
    schema: Mapping[str, Any], value: Any
) -> list[ValidationIssue] | None:
    try:
        validator = Draft202012Validator(dict(schema))
        errors = sorted(
            validator.iter_errors(value), key=lambda error: list(error.path)
        )
    except SchemaError as error:  # pragma: no cover - invalid hand-authored schema
        raise GapError(
            "The action schema is invalid.",
            code="INTERNAL",
            expose=False,
            cause=error,
        ) from error
    if not errors:
        return None
    issues: list[ValidationIssue] = []
    for error in errors:
        path = ".".join(str(part) for part in error.absolute_path)
        issues.append(
            ValidationIssue(
                path=path or "(root)",
                message=error.message,
                code=error.validator,
            )
        )
    return issues


def validate_value(schema: SchemaLike | None, value: Any) -> ValidationResult:
    """Validate a value, returning issues instead of raising.

    Pydantic inputs produce a model instance as ``data``; plain JSON Schema
    inputs return the original value unchanged.
    """
    if schema is None:
        return ValidationResult(success=True, data=value)
    if is_pydantic_model(schema):
        try:
            return ValidationResult(success=True, data=schema.model_validate(value))
        except ValidationError as error:
            return ValidationResult(success=False, issues=_pydantic_issues(error))
    issues = _json_schema_issues(schema, value)
    if issues is None:
        return ValidationResult(success=True, data=value)
    return ValidationResult(success=False, issues=issues)


def parse_value(schema: SchemaLike | None, value: Any, label: str = "input") -> Any:
    """Validate or raise ``GapError(INVALID_INPUT)`` with structured issues."""
    result = validate_value(schema, value)
    if result.success:
        return result.data
    raise invalid_input(
        f"Invalid {label}.",
        {"issues": [issue.to_dict() for issue in result.issues]},
    )


def is_object_schema(schema: Mapping[str, Any]) -> bool:
    """True when a schema describes an object-shaped MCP tool input."""
    return schema.get("type") == "object" or (
        schema.get("type") is None and isinstance(schema.get("properties"), Mapping)
    )


def schema_paths_without_descriptions(
    schema: Mapping[str, Any], prefix: str = ""
) -> list[str]:
    """Collect property paths that lack a non-empty description."""
    missing: list[str] = []
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return missing
    for key, raw_property in properties.items():
        if not isinstance(raw_property, Mapping):
            continue
        path = f"{prefix}.{key}" if prefix else str(key)
        description = raw_property.get("description")
        if not isinstance(description, str) or not description.strip():
            missing.append(path)
        if raw_property.get("type") == "object":
            missing.extend(schema_paths_without_descriptions(raw_property, path))
        items = raw_property.get("items")
        if raw_property.get("type") == "array" and isinstance(items, Mapping):
            missing.extend(schema_paths_without_descriptions(items, f"{path}[]"))
    return missing
