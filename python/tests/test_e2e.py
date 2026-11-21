"""End-to-end MCP round trips with the official SDK client."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from mcp import Client
from mcp.client.stdio import StdioServerParameters

from gapmcp import (
    ApiKeyAuth,
    ApiKeyRecord,
    GapPolicy,
    HmacApprovalGate,
    Principal,
    create_registry,
    create_server,
    define_action,
    define_policy,
)

SRC = str(Path(__file__).resolve().parents[1] / "src")


def build_server(**options):
    read = define_action(
        lambda input, ctx: {"value": input["value"]},
        name="demo.read",
        description="Read a value and return it through structured content.",
        input={
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "Value to return."}
            },
            "required": ["value"],
        },
        scopes=["demo:read"],
        tags=["read-only"],
    )
    write = define_action(
        lambda input, ctx: {"written": True},
        name="demo.write",
        description="Write a value; only principals with write scope can see it.",
        scopes=["demo:write"],
    )
    return create_server(create_registry(read, write), **options)


async def test_client_lists_tools_and_calls_one() -> None:
    server = build_server()
    async with Client(server.server) as client:
        tools = await client.list_tools()
        names = [tool.name for tool in tools.tools]
        assert "demo.read" in names
        assert "demo.write" in names
        assert "gap.receipts.get" in names

        result = await client.call_tool("demo.read", {"value": "hello"})
        assert result.is_error is False
        assert result.structured_content == {"value": "hello"}
        assert result.content[0].type == "text"
        assert "hello" in result.content[0].text


async def test_client_receives_structured_errors() -> None:
    server = build_server()
    async with Client(server.server) as client:
        invalid = await client.call_tool("demo.read", {})
        assert invalid.is_error is True
        assert invalid.structured_content["gapError"]["code"] == "INVALID_INPUT"

        unknown = await client.call_tool("demo.missing", {})
        assert unknown.is_error is True
        assert unknown.structured_content["gapError"]["code"] == "NOT_FOUND"


async def test_client_list_is_scope_filtered() -> None:
    server = build_server(
        auth=ApiKeyAuth(
            [ApiKeyRecord(key="unused", principal=Principal(id="usr_read"))]
        ),
        stdio_principal=Principal(id="usr_read", scopes=["demo:read"]),
    )
    async with Client(server.server) as client:
        tools = await client.list_tools()
        names = [tool.name for tool in tools.tools]
        assert "demo.read" in names
        assert "demo.write" not in names

        denied = await client.call_tool("demo.write", {})
        assert denied.is_error is True
        assert denied.structured_content["gapError"]["code"] == "FORBIDDEN"


async def test_client_call_goes_through_policy() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [
                    {
                        "tools": ["demo.write"],
                        "deny": True,
                        "reason": "Writes disabled in this environment.",
                    }
                ],
            }
        )
    )
    server = build_server(policy=policy)
    async with Client(server.server) as client:
        result = await client.call_tool("demo.write", {})
        assert result.is_error is True
        payload = result.structured_content["gapError"]
        assert payload["code"] == "POLICY_DENIED"
        assert "Writes disabled" in payload["message"]


async def test_client_records_audit_and_receipts() -> None:
    server = build_server()
    async with Client(server.server) as client:
        await client.call_tool("demo.read", {"value": "audited"})
        events = server.audit.list()
        assert len(events) == 1
        assert events[0].decision == "allowed"
        assert events[0].action == "demo.read"
        assert events[0].args_hash

        receipt = server.calls.list()[0]
        result = await client.call_tool("gap.receipts.get", {"receiptId": receipt.id})
        assert result.is_error is False
        assert result.structured_content["args"] == {"value": "audited"}


async def test_client_tools_have_annotations_and_schemas() -> None:
    server = build_server()
    async with Client(server.server) as client:
        tools = await client.list_tools()
        read = next(tool for tool in tools.tools if tool.name == "demo.read")
        assert read.input_schema["type"] == "object"
        assert read.annotations is not None
        assert read.annotations.read_only_hint is True


async def test_client_can_pass_an_approval_token_in_meta() -> None:
    gate = HmacApprovalGate("approval-secret", ttl_ms=60_000)
    action = define_action(
        lambda input, ctx: {"approved": True},
        name="demo.approved",
        description="A confirmed action used to verify approval token transport.",
        confirm=True,
    )
    server = create_server(create_registry(action), approvals=gate)
    token, _ = gate.issue(
        action="demo.approved",
        args={"id": "1"},
        principal_id="anonymous",
        approved_by="alice",
    )
    async with Client(server.server) as client:
        result = await client.call_tool(
            "demo.approved",
            {"id": "1"},
            meta={"gap/approval": token},
        )
        assert result.is_error is False
        assert result.structured_content == {"approved": True}


async def test_stdio_transport_round_trip() -> None:
    script = """
import asyncio
from gapmcp import create_registry, create_server, define_action

action = define_action(
    lambda input, ctx: {"echo": input.get("value")},
    name="demo.echo",
    description="Echo a value over a stdio MCP transport for testing.",
    input={
        "type": "object",
        "properties": {"value": {"type": "string", "description": "Value."}},
    },
)
server = create_server(create_registry(action))
asyncio.run(server.run_stdio())
"""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-c", script],
        env={**os.environ, "PYTHONPATH": SRC},
    )
    async with Client(parameters, read_timeout_seconds=20) as client:
        tools = await client.list_tools()
        assert "demo.echo" in [tool.name for tool in tools.tools]
        result = await client.call_tool("demo.echo", {"value": "stdio"})
        assert result.is_error is False
        assert result.structured_content == {"echo": "stdio"}
