import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineAction } from "gapmcp-core";
import { callAction, testContext, testPrincipal } from "../src/index";

const echo = defineAction({
  name: "test.echo",
  description: "Echo a message back to the caller. Pure and side-effect free.",
  input: z.object({ message: z.string() }),
  execute: ({ message }, ctx) => ({ message, actor: ctx.principal.id }),
});

describe("testing harness", () => {
  it("builds a principal with all scopes", () => {
    expect(testPrincipal().scopes).toEqual(["*"]);
    expect(testPrincipal({ id: "usr_42", scopes: ["a"] }).id).toBe("usr_42");
  });

  it("builds a context with a live signal and trace id", () => {
    const ctx = testContext();
    expect(ctx.signal.aborted).toBe(false);
    expect(ctx.traceId.startsWith("trace_")).toBe(true);
    expect(ctx.dryRun).toBe(false);
  });

  it("validates and calls an action", async () => {
    await expect(callAction(echo, { message: "hi" })).resolves.toEqual({
      message: "hi",
      actor: "usr_test",
    });
  });

  it("rejects invalid input", async () => {
    await expect(callAction(echo, { message: 4 })).rejects.toMatchObject({
      code: "INVALID_INPUT",
    });
  });
});
