"""Action definition, composition and direct execution."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, Field

from gapmcp import (
    Action,
    GapError,
    define_action,
    define_actions,
    define_skill,
    is_action,
    is_action_array,
    run_action,
)
from gapmcp.testing import test_context as make_context


class EchoInput(BaseModel):
    message: str = Field(min_length=1, description="Text to echo.")


async def echo(input: EchoInput, ctx):
    return {"echo": input.message, "principal": ctx.principal.id}


def test_decorator_infers_name_and_description() -> None:
    @define_action(
        name="demo.echo",
        description="Echo a message back to the caller for testing purposes.",
        input=EchoInput,
        tags=["demo"],
        scopes=["demo:read"],
    )
    async def handler(input, ctx):
        return input

    assert isinstance(handler, Action)
    assert handler.name == "demo.echo"
    assert handler.description.startswith("Echo a message")
    assert handler.tags == ["demo"]
    assert handler.scopes == ["demo:read"]


def test_direct_call_with_function() -> None:
    async def handler(input, ctx):
        """Return the input unchanged."""
        return input

    created = define_action(
        handler,
        name="demo.passthrough",
        description="Return the input unchanged, useful for transport tests.",
    )
    assert created.execute is handler
    assert created.description.startswith("Return the input")


def test_template_then_decorate() -> None:
    async def draft(input, ctx):
        return "draft"

    template = define_action(
        draft,
        name="demo.template",
        description="Template action used to check decorator composition.",
        scopes=["demo:write"],
    )
    assert isinstance(template, Action)

    async def handler(input, ctx):
        return "ok"

    created = define_action(template)(handler)
    assert created.execute is handler
    assert created.name == "demo.template"
    assert created.scopes == ["demo:write"]


def test_direct_call_with_execute_keyword() -> None:
    async def handler(input, ctx):
        return input

    created = define_action(
        name="demo.direct",
        description="Direct action built from an execute keyword argument.",
        execute=handler,
    )
    assert created.execute is handler


def test_names_are_normalized() -> None:
    created = define_action(
        lambda input, ctx: None,
        name="  demo   spaced  ",
        description="An action whose name is normalized before registration.",
    )
    assert created.name == "demo.spaced"


def test_rejects_unknown_risk_and_bad_timeout() -> None:
    with pytest.raises(GapError) as risk_error:
        define_action(
            lambda input, ctx: None,
            name="demo.risk",
            description="An action with an invalid risk level for validation.",
            risk="extreme",
        )
    assert risk_error.value.code == "INVALID_INPUT"

    with pytest.raises(GapError):
        define_action(
            lambda input, ctx: None,
            name="demo.timeout",
            description="An action with an invalid timeout configuration.",
            timeout_ms=0,
        )


def test_name_only_returns_a_decorator() -> None:
    decorate = define_action(
        name="demo.empty",
        description="An action assembled by a template decorator.",
    )
    assert callable(decorate)

    async def handler(input, ctx):
        return {"ok": True}

    created = decorate(handler)
    assert isinstance(created, Action)
    assert created.name == "demo.empty"


def test_define_actions_and_guards() -> None:
    first = define_action(
        lambda input, ctx: input,
        name="demo.one",
        description="The first action in the guard test collection here.",
    )
    second = define_action(
        lambda input, ctx: input,
        name="demo.two",
        description="The second action in the guard test collection here.",
    )
    actions = define_actions(first, second)
    assert actions == [first, second]
    assert is_action(first)
    assert is_action({"name": "x", "execute": lambda: None})
    assert not is_action({"name": "x"})
    assert is_action_array(actions)
    assert not is_action_array([first, "nope"])


async def test_run_action_validates_child_input() -> None:
    child = define_action(
        echo,
        name="demo.echo",
        description="Echo a message back to the caller for testing purposes.",
        input=EchoInput,
    )
    ctx = make_context()
    assert (await run_action(child, {"message": "hi"}, ctx))["echo"] == "hi"

    with pytest.raises(GapError) as error:
        await run_action(child, {"message": ""}, ctx)
    assert error.value.code == "INVALID_INPUT"


async def test_skill_merges_scopes_and_runs_children() -> None:
    child = define_action(
        echo,
        name="demo.child",
        description="A child action used from a skill composition test.",
        input=EchoInput,
        scopes=["demo:read"],
    )

    @define_skill(
        uses=[child],
        name="demo.skill",
        description="Compose the child action while carrying its scopes.",
        scopes=["demo:write"],
    )
    async def skill(input, ctx, run):
        result = await run(child, input)
        return {"wrapped": result}

    assert set(skill.scopes) == {"demo:read", "demo:write"}
    result = await skill.execute({"message": "hi"}, make_context())
    assert result["wrapped"]["echo"] == "hi"
