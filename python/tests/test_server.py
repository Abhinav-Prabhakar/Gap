"""Server pipeline: visibility, errors, policy, limits, approvals and meta tools."""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlparse

import pytest
from pydantic import BaseModel, Field

from gapmcp import (
    ActionUiBinding,
    GapPolicy,
    HmacApprovalGate,
    MemoryAuditLog,
    Principal,
    RateLimit,
    define_action,
    define_policy,
    create_registry,
    create_server,
    verify_handoff_state,
)
from gapmcp.testing import call_tool


class EchoInput(BaseModel):
    message: str = Field(description="Message to echo.")


class EchoOutput(BaseModel):
    echo: str = Field(description="The echoed message.")


def echo_action(**kwargs):
    defaults = dict(
        name="demo.echo",
        description="Echo a message back to the caller for pipeline tests.",
        input=EchoInput,
        output=EchoOutput,
        scopes=["demo:read"],
    )
    defaults.update(kwargs)
    return define_action(lambda input, ctx: {"echo": input.message}, **defaults)


def principal(scopes=("*",), principal_id="usr_1") -> Principal:
    return Principal(id=principal_id, scopes=list(scopes))


async def test_list_tools_is_scope_filtered() -> None:
    public = define_action(
        lambda input, ctx: {"ok": True},
        name="public.ping",
        description="A public ping action visible without any scopes.",
    )
    invoice = define_action(
        lambda input, ctx: {"ok": True},
        name="invoices.create",
        description="Create an invoice; visible only to invoice writers.",
        scopes=["invoices:write"],
    )
    server = create_server(create_registry(public, invoice))

    all_names = [tool.name for tool in server.list_tools(principal(["*"]))]
    assert "invoices.create" in all_names
    assert "public.ping" in all_names

    limited = [tool.name for tool in server.list_tools(principal(["demo:read"]))]
    assert "public.ping" in limited
    assert "invoices.create" not in limited
    assert "gap.receipts.get" in limited


async def test_success_returns_text_and_structured_content() -> None:
    server = create_server(create_registry(echo_action()))
    result = await call_tool(server, "demo.echo", {"message": "hello"})
    assert result["isError"] is False
    assert json.loads(result["text"]) == {"echo": "hello"}
    assert result["structured"] == {"echo": "hello"}


async def test_invalid_input_is_structured() -> None:
    server = create_server(create_registry(echo_action()))
    result = await call_tool(server, "demo.echo", {"message": 42})
    assert result["isError"] is True
    payload = result["structured"]["gapError"]
    assert payload["code"] == "INVALID_INPUT"
    assert payload["status"] == 400
    assert payload["details"]["issues"][0]["path"] == "message"

    missing = await call_tool(server, "demo.echo", {})
    assert missing["structured"]["gapError"]["code"] == "INVALID_INPUT"


async def test_unknown_action_is_not_found() -> None:
    server = create_server(create_registry(echo_action()))
    result = await call_tool(server, "demo.missing", {})
    assert result["isError"] is True
    assert result["structured"]["gapError"]["code"] == "NOT_FOUND"


async def test_scope_denial() -> None:
    server = create_server(create_registry(echo_action()))
    result = await call_tool(
        server, "demo.echo", {"message": "hi"}, scopes=["other:read"]
    )
    assert result["isError"] is True
    payload = result["structured"]["gapError"]
    assert payload["code"] == "FORBIDDEN"
    assert payload["details"]["missingScopes"] == ["demo:read"]


async def test_policy_denial_and_reason() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [
                    {
                        "tools": ["demo.echo"],
                        "deny": True,
                        "reason": "Echo is disabled.",
                    }
                ],
            }
        )
    )
    server = create_server(create_registry(echo_action()), policy=policy)
    result = await call_tool(server, "demo.echo", {"message": "hi"})
    assert result["isError"] is True
    payload = result["structured"]["gapError"]
    assert payload["code"] == "POLICY_DENIED"
    assert "Echo is disabled." in payload["message"]


async def test_policy_limit_denial() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [{"tools": ["demo.echo"], "maxAmount": 10}],
            }
        )
    )
    action = define_action(
        lambda input, ctx: {"ok": True},
        name="demo.echo",
        description="Echo a message, used with a policy amount limit test.",
        input={
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message."},
                "amount": {"type": "number", "description": "Amount."},
            },
            "required": ["message"],
        },
    )
    server = create_server(create_registry(action), policy=policy)
    result = await call_tool(server, "demo.echo", {"message": "hi", "amount": 50})
    assert result["isError"] is True
    payload = result["structured"]["gapError"]
    assert payload["code"] == "POLICY_DENIED"
    assert payload["details"]["code"] == "LIMIT_EXCEEDED"


async def test_output_redaction_applies_to_result_and_receipt() -> None:
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [{"tools": ["users.get"], "redact": ["email"]}],
            }
        )
    )
    action = define_action(
        lambda input, ctx: {"id": "usr_1", "email": "secret@example.com"},
        name="users.get",
        description="Fetch a user record, with sensitive email redaction.",
    )
    server = create_server(
        create_registry(action), policy=policy, audit=MemoryAuditLog()
    )
    result = await call_tool(server, "users.get", {})
    assert result["structured"]["email"] == "[REDACTED]"
    assert "secret@example.com" not in result["text"]

    receipt = server.calls.list()[0]
    assert receipt.result["email"] == "[REDACTED]"
    assert "secret@example.com" not in json.dumps(
        [event.to_dict() for event in server.audit.list()]
    )


async def test_rate_limit_per_principal_and_tool() -> None:
    server = create_server(
        create_registry(echo_action()),
        rate_limit=RateLimit(limit=1, window_ms=60_000),
    )
    first = await call_tool(server, "demo.echo", {"message": "one"})
    second = await call_tool(server, "demo.echo", {"message": "two"})
    assert first["isError"] is False
    assert second["isError"] is True
    payload = second["structured"]["gapError"]
    assert payload["code"] == "RATE_LIMITED"
    assert payload["details"]["retryAfterMs"] >= 1

    # A different principal has its own bucket.
    other = await call_tool(
        server,
        "demo.echo",
        {"message": "three"},
        principal=principal(principal_id="usr_2"),
    )
    assert other["isError"] is False


async def test_idempotent_action_replays_result() -> None:
    counter = {"value": 0}

    def execute(input, ctx):
        counter["value"] += 1
        return {"calls": counter["value"]}

    action = define_action(
        execute,
        name="demo.idempotent",
        description="Count executions while declaring idempotent retry behavior.",
        input={"type": "object", "properties": {}},
        idempotent=True,
    )
    server = create_server(create_registry(action), audit=MemoryAuditLog())
    first = await call_tool(server, "demo.idempotent", {})
    second = await call_tool(server, "demo.idempotent", {})
    assert first["structured"] == {"calls": 1}
    assert second["structured"] == {"calls": 1}
    assert counter["value"] == 1
    decisions = [event.decision for event in server.audit.list()]
    assert decisions == ["allowed", "allowed"]
    replay = server.audit.list()[1]
    assert replay.metadata == {"idempotentReplay": True}


async def test_inflight_idempotent_calls_are_deduplicated() -> None:
    counter = {"value": 0}
    started = asyncio.Event()
    release = asyncio.Event()

    async def execute(input, ctx):
        started.set()
        await release.wait()
        counter["value"] += 1
        return {"calls": counter["value"]}

    action = define_action(
        execute,
        name="demo.slow",
        description="A slow idempotent action used to verify in-flight dedupe.",
        idempotent=True,
    )
    server = create_server(create_registry(action))
    first_task = asyncio.create_task(call_tool(server, "demo.slow", {}))
    await started.wait()
    second_task = asyncio.create_task(call_tool(server, "demo.slow", {}))
    await asyncio.sleep(0)
    release.set()
    first, second = await asyncio.gather(first_task, second_task)
    assert first["structured"] == {"calls": 1}
    assert second["structured"] == {"calls": 1}
    assert counter["value"] == 1


async def test_explicit_idempotency_key_via_meta() -> None:
    counter = {"value": 0}

    def execute(input, ctx):
        counter["value"] += 1
        return {"calls": counter["value"], "arg": input.get("arg")}

    action = define_action(
        execute,
        name="demo.keyed",
        description="An action used to verify explicit idempotency key handling.",
        input={"type": "object", "properties": {"arg": {"type": "integer"}}},
    )
    server = create_server(create_registry(action))
    first = await call_tool(
        server, "demo.keyed", {"arg": 1}, meta={"idempotencyKey": "fixed"}
    )
    second = await call_tool(
        server, "demo.keyed", {"arg": 2}, meta={"idempotencyKey": "fixed"}
    )
    assert first["structured"] == {"calls": 1, "arg": 1}
    assert second["structured"] == first["structured"]
    assert counter["value"] == 1


async def test_audit_event_hashes_args_and_records_decisions() -> None:
    audit = MemoryAuditLog()
    server = create_server(create_registry(echo_action()), audit=audit)
    await call_tool(server, "demo.echo", {"message": "top-secret"})
    await call_tool(server, "demo.echo", {"message": 42})
    await call_tool(server, "demo.echo", {"message": "x"}, scopes=["nothing"])

    events = [event.to_dict() for event in audit.list()]
    assert [event["decision"] for event in events] == ["allowed", "error", "denied"]
    assert all("argsHash" in event for event in events)
    assert "top-secret" not in json.dumps(events)
    assert all(event["traceId"] for event in events)


async def test_receipt_meta_tool_checks_ownership() -> None:
    server = create_server(create_registry(echo_action()))
    await call_tool(server, "demo.echo", {"message": "hi"})
    receipt = server.calls.list()[0]

    result = await call_tool(server, "gap.receipts.get", {"receiptId": receipt.id})
    assert result["isError"] is False
    assert result["structured"]["receiptId"] == receipt.id
    assert result["structured"]["args"] == {"message": "hi"}

    other = await call_tool(
        server,
        "gap.receipts.get",
        {"receiptId": receipt.id},
        principal=principal(principal_id="usr_2"),
    )
    assert other["structured"]["gapError"]["code"] == "NOT_FOUND"


async def test_undo_meta_tool_runs_the_undo_handler() -> None:
    undone = []

    def execute(input, ctx):
        return {"id": "inv_1", "created": True}

    def undo(result, input, ctx):
        undone.append((result, input, ctx.principal.id))
        return None

    action = define_action(
        execute,
        name="invoices.create",
        description="Create an invoice, with a best-effort undo handler attached.",
        undo=undo,
        idempotent=True,
    )
    server = create_server(create_registry(action))
    await call_tool(server, "invoices.create", {"amount": 10})
    receipt = server.calls.list()[0]
    assert receipt.undo_available is True

    result = await call_tool(server, "gap.undo", {"receiptId": receipt.id})
    assert result["isError"] is False
    assert result["structured"]["status"] == "undone"
    assert undone == [({"id": "inv_1", "created": True}, {"amount": 10}, "anonymous")]
    assert server.calls.get(receipt.id).undone is True  # type: ignore[union-attr]

    again = await call_tool(server, "gap.undo", {"receiptId": receipt.id})
    assert again["structured"]["gapError"]["code"] == "CONFLICT"


async def test_task_creation_polling_and_cancel() -> None:
    release = asyncio.Event()

    async def execute(input, ctx):
        await release.wait()
        return {"done": True}

    action = define_action(
        execute,
        name="reports.build",
        description="Build a report in the background as a long-running task.",
        task=True,
    )
    server = create_server(create_registry(action))
    names = [tool.name for tool in server.list_tools()]
    assert "gap.tasks.get" in names and "gap.tasks.cancel" in names

    started = await call_tool(server, "reports.build", {})
    assert started["isError"] is False
    assert started["structured"]["status"] == "working"
    task_id = started["structured"]["taskId"]

    status = await call_tool(server, "gap.tasks.get", {"taskId": task_id})
    assert status["structured"]["status"] == "working"

    release.set()
    for _ in range(50):
        status = await call_tool(server, "gap.tasks.get", {"taskId": task_id})
        if status["structured"]["status"] == "completed":
            break
        await asyncio.sleep(0.01)
    assert status["structured"]["status"] == "completed"
    assert status["structured"]["result"] == {"done": True}


async def test_task_cancel_aborts_signal() -> None:
    started = asyncio.Event()
    aborted = asyncio.Event()

    async def execute(input, ctx):
        ctx.signal.add_callback(aborted.set)
        started.set()
        await asyncio.sleep(10)
        return {"done": True}

    action = define_action(
        execute,
        name="reports.cancel",
        description="A background report task used to verify cancellation.",
        task=True,
    )
    server = create_server(create_registry(action))
    started_result = await call_tool(server, "reports.cancel", {})
    task_id = started_result["structured"]["taskId"]
    await started.wait()

    cancelled = await call_tool(server, "gap.tasks.cancel", {"taskId": task_id})
    assert cancelled["isError"] is False
    assert cancelled["structured"]["status"] == "cancelled"
    await asyncio.wait_for(aborted.wait(), timeout=2)


async def test_approval_store_approve_then_retry() -> None:
    executed = []
    action = define_action(
        lambda input, ctx: executed.append(input) or {"ok": True},
        name="invoices.delete",
        description="Delete an invoice permanently after human approval.",
        confirm=True,
    )
    server = create_server(create_registry(action))
    first = await call_tool(server, "invoices.delete", {"id": "inv_1"})
    assert first["isError"] is False
    assert first["structured"]["status"] == "approval_required"
    approval_id = first["structured"]["approvalId"]
    assert executed == []

    # Different arguments do not match the pending approval.
    server.approve(approval_id, "alice")
    still_pending = await call_tool(server, "invoices.delete", {"id": "inv_2"})
    assert still_pending["structured"]["status"] == "approval_required"
    assert executed == []

    approved = await call_tool(server, "invoices.delete", {"id": "inv_1"})
    assert approved["isError"] is False
    assert approved["structured"] == {"ok": True}
    assert executed == [{"id": "inv_1"}]

    again = await call_tool(server, "invoices.delete", {"id": "inv_1"})
    assert again["structured"]["status"] == "approval_required"


async def test_idempotent_confirm_action_is_not_cached_as_approval() -> None:
    executed = []
    action = define_action(
        lambda input, ctx: executed.append(input) or {"ok": True},
        name="invoices.delete",
        description="Delete an invoice permanently after human approval.",
        confirm=True,
        idempotent=True,
    )
    server = create_server(create_registry(action))
    first = await call_tool(server, "invoices.delete", {"id": "inv_1"})
    assert first["structured"]["status"] == "approval_required"
    server.approve(first["structured"]["approvalId"], "alice")
    second = await call_tool(server, "invoices.delete", {"id": "inv_1"})
    assert second["isError"] is False
    assert second["structured"] == {"ok": True}
    assert executed == [{"id": "inv_1"}]
    third = await call_tool(server, "invoices.delete", {"id": "inv_1"})
    assert third["structured"] == {"ok": True}
    assert executed == [{"id": "inv_1"}]


async def test_hmac_approval_token_is_accepted() -> None:
    gate = HmacApprovalGate("approval-secret", ttl_ms=60_000)
    action = define_action(
        lambda input, ctx: {"approved": True},
        name="invoices.delete",
        description="Delete an invoice permanently after human approval.",
        confirm=True,
    )
    server = create_server(create_registry(action), approvals=gate)
    token, _ = gate.issue(
        action="invoices.delete",
        args={"id": "inv_1"},
        principal_id="anonymous",
        approved_by="alice",
    )
    result = await call_tool(
        server,
        "invoices.delete",
        {"id": "inv_1"},
        meta={"gap/approval": token},
    )
    assert result["isError"] is False
    assert result["structured"] == {"approved": True}

    bad = await call_tool(
        server,
        "invoices.delete",
        {"id": "inv_2"},
        meta={"gap/approval": token},
    )
    assert bad["structured"]["gapError"]["code"] == "APPROVAL_REQUIRED"


async def test_confirm_callable_is_evaluated_with_validated_input() -> None:
    action = define_action(
        lambda input, ctx: {"ok": True},
        name="invoices.create",
        description="Create an invoice, confirming only large amounts with a human.",
        input={
            "type": "object",
            "properties": {"amount": {"type": "number", "description": "Amount."}},
            "required": ["amount"],
        },
        confirm=lambda input, ctx: input["amount"] > 100,
    )
    server = create_server(create_registry(action))
    small = await call_tool(server, "invoices.create", {"amount": 10})
    assert small["isError"] is False
    large = await call_tool(server, "invoices.create", {"amount": 500})
    assert large["structured"]["status"] == "approval_required"


async def test_timeout_aborts_the_signal() -> None:
    observed = []

    async def execute(input, ctx):
        try:
            await asyncio.sleep(1)
        finally:
            observed.append(ctx.signal.aborted)

    action = define_action(
        execute,
        name="demo.slow",
        description="A deliberately slow action used to verify the timeout path.",
        timeout_ms=20,
    )
    server = create_server(create_registry(action))
    result = await call_tool(server, "demo.slow", {})
    assert result["isError"] is True
    assert result["structured"]["gapError"]["code"] == "TIMEOUT"
    assert observed == [True]


async def test_output_validation_failure_is_internal() -> None:
    class Output(BaseModel):
        count: int = Field(description="Count.")

    action = define_action(
        lambda input, ctx: {"count": "not-a-number"},
        name="demo.output",
        description="Return a deliberately invalid output for validation tests.",
        output=Output,
    )
    server = create_server(create_registry(action))
    result = await call_tool(server, "demo.output", {})
    assert result["isError"] is True
    assert result["structured"]["gapError"]["code"] == "INTERNAL"


async def test_dry_run_policy_is_visible_to_the_action() -> None:
    seen = []

    def execute(input, ctx):
        seen.append(ctx.dry_run)
        return {"dryRun": ctx.dry_run}

    action = define_action(
        execute,
        name="invoices.send",
        description="Send an invoice, with a policy-requested dry-run mode.",
    )
    policy = GapPolicy(
        define_policy(
            {
                "version": 1,
                "rules": [{"tools": ["invoices.send"], "dryRun": True}],
            }
        )
    )
    server = create_server(create_registry(action), policy=policy)
    result = await call_tool(server, "invoices.send", {})
    assert result["structured"] == {"dryRun": True}
    assert seen == [True]
    decisions = [event.decision for event in server.audit.list()]
    assert decisions == ["dry_run"]


async def test_handoff_meta_tool_creates_signed_url() -> None:
    action = define_action(
        lambda input, ctx: {"ok": True},
        name="invoices.create",
        description="Create an invoice, with a UI binding for human handoff.",
        ui=ActionUiBinding(route="/invoices/new"),
    )
    server = create_server(
        create_registry(action),
        base_url="https://app.example.com",
        handoff_secret="handoff-secret",
    )
    assert "gap.handoff" in [tool.name for tool in server.list_tools()]
    result = await call_tool(
        server,
        "gap.handoff",
        {"action": "invoices.create", "args": {"amount": 10}},
    )
    assert result["isError"] is False
    url = result["structured"]["url"]
    assert url.startswith("https://app.example.com/invoices/new?gap_state=")
    token = parse_qs(urlparse(url).query)["gap_state"][0]
    payload = verify_handoff_state(token, "handoff-secret")
    assert payload is not None
    assert payload["action"] == "invoices.create"


async def test_search_meta_tool_appears_above_twelve_actions() -> None:
    actions = [
        define_action(
            lambda input, ctx: {"ok": True},
            name=f"demo.action{i}",
            description=f"Demo action number {i} used for search threshold tests.",
        )
        for i in range(13)
    ]
    server = create_server(create_registry(*actions))
    names = [tool.name for tool in server.list_tools()]
    assert "gap.search" in names

    result = await call_tool(server, "gap.search", {"query": "demo action"})
    assert result["isError"] is False
    assert result["structured"]["count"] > 0
    assert all(
        hit["name"].startswith("demo.") for hit in result["structured"]["results"]
    )


async def test_search_is_scope_filtered() -> None:
    actions = [
        define_action(
            lambda input, ctx: {"ok": True},
            name=f"invoices.action{i}",
            description=f"Invoice action {i} used for scoped search results.",
            scopes=["invoices:read"],
        )
        for i in range(13)
    ]
    server = create_server(create_registry(*actions))
    result = await call_tool(
        server, "gap.search", {"query": "invoice"}, scopes=["nothing"]
    )
    assert result["structured"]["count"] == 0


async def test_on_call_callback_and_bounded_receipts() -> None:
    recorded = []
    server = create_server(
        create_registry(echo_action()),
        call_store_limit=1,
        on_call=lambda record: recorded.append(record.id),
    )
    await call_tool(server, "demo.echo", {"message": "one"})
    await call_tool(server, "demo.echo", {"message": "two"})
    assert len(recorded) == 2
    assert len(server.calls.list()) == 1
    assert server.calls.list()[0].args == {"message": "two"}


async def test_receipts_meta_tool_is_hidden_when_the_store_is_disabled() -> None:
    server = create_server(create_registry(echo_action()), call_store_limit=0)
    assert "gap.receipts.get" not in [tool.name for tool in server.list_tools()]
    result = await call_tool(server, "gap.receipts.get", {"receiptId": "rcp_x"})
    assert result["structured"]["gapError"]["code"] == "NOT_FOUND"


async def test_reserved_meta_names_are_rejected() -> None:
    action = define_action(
        lambda input, ctx: {"ok": True},
        name="gap.search",
        description="A user action that collides with a reserved meta-tool name.",
    )
    with pytest.raises(Exception) as error:
        create_server(create_registry(action))
    assert "reserved" in str(error.value)
