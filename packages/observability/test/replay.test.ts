import { describe, expect, it } from "vitest";
import { ActionRegistry, GapError, defineAction } from "gapmcp-core";
import type { AnyAction } from "gapmcp-core";
import { ReplayRecorder, recordedCallFingerprint } from "../src/index";

const add = defineAction<{ a: number; b: number }, { sum: number }>({
  name: "math.add",
  description: "Add two numbers. Used by the replay recorder tests.",
  execute: (input) => ({ sum: input.a + input.b }),
});

const inspect = defineAction<
  { label?: string },
  {
    dryRun: boolean;
    principalId: string;
    scopes: string[];
    tenantId?: string;
  }
>({
  name: "ctx.inspect",
  description: "Return the action context. Used by the replay recorder tests.",
  execute: (_input, ctx) => ({
    dryRun: ctx.dryRun,
    principalId: ctx.principal.id,
    scopes: ctx.scopes,
    ...(ctx.tenantId === undefined ? {} : { tenantId: ctx.tenantId }),
  }),
});

const failing = defineAction({
  name: "math.fail",
  description: "Always throw a GapError. Used by the replay recorder tests.",
  execute: () => {
    throw new GapError("Cannot divide by zero.", { code: "INVALID_INPUT" });
  },
});

const mutating = defineAction<{ value: number }, { value: number }>({
  name: "math.mutate",
  description: "Mutate its input. Used to prove replay never changes entries.",
  execute: (input) => {
    input.value = 99;
    return input;
  },
});

const secretRead = defineAction({
  name: "secret.read",
  description: "Return a secret. Used to check replay-time redaction.",
  execute: () => ({ secret: "live-secret", ok: true }),
});

const registry = new ActionRegistry([
  add,
  inspect,
  failing,
  mutating,
  secretRead,
] as AnyAction[]);

function captureGapError(run: () => unknown): GapError {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(GapError);
    return error as GapError;
  }
  throw new Error("Expected the call to throw a GapError.");
}

describe("ReplayRecorder recording", () => {
  it("assigns an id and injectable timestamp", () => {
    const recorder = new ReplayRecorder({ now: () => 5000 });
    const call = recorder.record({
      action: "math.add",
      args: { a: 1, b: 2 },
      principalId: "user_1",
      durationMs: 12,
    });

    expect(call.id).toMatch(/^call_/);
    expect(call.timestamp).toBe(new Date(5000).toISOString());
    expect(call.durationMs).toBe(12);
    expect(recorder.entries()).toHaveLength(1);
  });

  it("redacts configured argument and result paths without mutating input", () => {
    const recorder = new ReplayRecorder({
      redact: ["card.number", "secret"],
    });
    const args = {
      card: { number: "4242", holder: "Ada" },
      secret: "s3cr3t",
      keep: true,
    };
    const result = { secret: "result-secret", ok: true };

    const call = recorder.record({
      action: "math.add",
      args,
      result,
      principalId: "user_1",
      durationMs: 3,
    });

    expect(call.args).toEqual({
      card: { number: "[REDACTED]", holder: "Ada" },
      secret: "[REDACTED]",
      keep: true,
    });
    expect(call.result).toEqual({ secret: "[REDACTED]", ok: true });
    expect(args.card.number).toBe("4242");
    expect(args.secret).toBe("s3cr3t");
    expect(result.secret).toBe("result-secret");
  });

  it("returns entry snapshots that cannot be used to mutate storage", () => {
    const recorder = new ReplayRecorder();
    recorder.record({
      action: "math.add",
      args: { a: 1, b: 2 },
      principalId: "user_1",
      durationMs: 1,
    });

    const snapshot = recorder.entries();
    snapshot[0]!.action = "tampered.action";
    expect(recorder.entries()[0]!.action).toBe("math.add");
  });
});

describe("ReplayRecorder replay", () => {
  it("executes recorded actions in order with a test context", async () => {
    const recorder = new ReplayRecorder();
    const first = recorder.record({
      action: "math.add",
      args: { a: 2, b: 3 },
      principalId: "user_42",
      tenantId: "tenant_9",
      durationMs: 8,
    });
    const second = recorder.record({
      action: "ctx.inspect",
      args: { label: "hello" },
      principalId: "user_42",
      tenantId: "tenant_9",
      durationMs: 2,
    });

    const results = await recorder.replay(registry);

    expect(results).toHaveLength(2);
    expect(results[0]).toMatchObject({
      id: first.id,
      action: "math.add",
      ok: true,
      result: { sum: 5 },
    });
    expect(results[0]!.durationMs).toBeGreaterThanOrEqual(0);
    expect(results[1]!.result).toEqual({
      dryRun: false,
      principalId: "user_42",
      scopes: [],
      tenantId: "tenant_9",
    });
    expect(results[1]!.id).toBe(second.id);
  });

  it("uses the supplied principal and dryRun flag", async () => {
    const recorder = new ReplayRecorder();
    recorder.record({
      action: "ctx.inspect",
      args: {},
      principalId: "original_user",
      tenantId: "original_tenant",
      durationMs: 0,
    });

    const [result] = await recorder.replay(registry, {
      principal: {
        id: "replayer",
        scopes: ["replay:run"],
        tenantId: "tenant_new",
      },
      dryRun: true,
    });

    expect(result!.result).toEqual({
      dryRun: true,
      principalId: "replayer",
      scopes: ["replay:run"],
      tenantId: "tenant_new",
    });
  });

  it("reports NOT_FOUND for an action that is no longer registered", async () => {
    const recorder = new ReplayRecorder();
    const call = recorder.record({
      action: "missing.tool",
      args: {},
      principalId: "user_1",
      durationMs: 0,
    });

    const [result] = await recorder.replay(registry);

    expect(result).toEqual({
      id: call.id,
      action: "missing.tool",
      ok: false,
      error: {
        code: "NOT_FOUND",
        message: 'Unknown action "missing.tool".',
      },
      durationMs: 0,
    });
  });

  it("captures failures and keeps replaying later calls", async () => {
    const recorder = new ReplayRecorder();
    const failed = recorder.record({
      action: "math.fail",
      args: {},
      principalId: "user_1",
      durationMs: 0,
    });
    const succeeded = recorder.record({
      action: "math.add",
      args: { a: 1, b: 1 },
      principalId: "user_1",
      durationMs: 0,
    });

    const results = await recorder.replay(registry);

    expect(results[0]).toMatchObject({
      id: failed.id,
      ok: false,
      error: { code: "INVALID_INPUT", message: "Cannot divide by zero." },
    });
    expect(results[1]).toMatchObject({
      id: succeeded.id,
      ok: true,
      result: { sum: 2 },
    });
  });

  it("redacts replay results with the recorder configuration", async () => {
    const recorder = new ReplayRecorder({ redact: ["secret"] });
    recorder.record({
      action: "secret.read",
      args: {},
      principalId: "user_1",
      durationMs: 0,
    });

    const [result] = await recorder.replay(registry);

    expect(result!.result).toEqual({ secret: "[REDACTED]", ok: true });
  });

  it("never mutates stored entries when an action mutates its input", async () => {
    const recorder = new ReplayRecorder();
    const call = recorder.record({
      action: "math.mutate",
      args: { value: 1 },
      principalId: "user_1",
      durationMs: 0,
    });

    const [result] = await recorder.replay(registry);

    expect(result!.ok).toBe(true);
    expect(result!.result).toEqual({ value: 99 });
    expect(recorder.entries()[0]!.args).toEqual({ value: 1 });
    expect(call.args).toEqual({ value: 1 });
  });

  it("measures replay duration with the injected clock", async () => {
    let tick = 1000;
    const recorder = new ReplayRecorder({
      now: () => {
        const value = tick;
        tick += 5;
        return value;
      },
    });
    recorder.record({
      action: "math.add",
      args: { a: 1, b: 2 },
      principalId: "user_1",
      durationMs: 0,
    });

    const [result] = await recorder.replay(registry);
    expect(result!.durationMs).toBe(5);
  });
});

describe("ReplayRecorder serialization", () => {
  it("round-trips recorded calls through JSON", () => {
    const recorder = new ReplayRecorder({ redact: ["card.number"] });
    recorder.record({
      action: "math.add",
      args: { a: 1, b: 2, card: { number: "4242" } },
      result: { sum: 3 },
      principalId: "user_1",
      durationMs: 4,
    });

    const restored = ReplayRecorder.fromJSON(recorder.toJSON());
    expect(restored.entries()).toEqual(recorder.entries());
    expect(Array.isArray(JSON.parse(recorder.toJSON()))).toBe(true);
  });

  it("accepts a versioned envelope and restores its redaction config", () => {
    const recorder = new ReplayRecorder({ redact: ["card.number"] });
    recorder.record({
      action: "math.add",
      args: { a: 1, b: 2, card: { number: "4242" } },
      principalId: "user_1",
      durationMs: 4,
    });

    const restored = ReplayRecorder.fromJSON(
      JSON.stringify({
        version: 1,
        redact: ["card.number"],
        calls: recorder.entries(),
      }),
    );
    expect(restored.entries()).toEqual(recorder.entries());

    const added = restored.record({
      action: "math.add",
      args: { a: 1, b: 2, card: { number: "5555" } },
      principalId: "user_1",
      durationMs: 1,
    });
    expect(added.args).toEqual({
      a: 1,
      b: 2,
      card: { number: "[REDACTED]" },
    });
  });

  it("accepts a plain JSON array of calls", () => {
    const recorder = new ReplayRecorder();
    recorder.record({
      action: "math.add",
      args: { a: 1, b: 2 },
      principalId: "user_1",
      durationMs: 1,
    });

    const restored = ReplayRecorder.fromJSON(
      JSON.stringify(recorder.entries()),
    );
    expect(restored.entries()).toEqual(recorder.entries());
  });

  it("rejects malformed or unsupported replay data with INVALID_INPUT", () => {
    const malformed = captureGapError(() => ReplayRecorder.fromJSON("{"));
    expect(malformed.code).toBe("INVALID_INPUT");
    expect(malformed.details).toMatchObject({ issues: expect.any(Array) });

    const unsupported = captureGapError(() =>
      ReplayRecorder.fromJSON(JSON.stringify({ version: 2, calls: [] })),
    );
    expect(unsupported.code).toBe("INVALID_INPUT");
    expect(unsupported.details).toMatchObject({
      issues: expect.arrayContaining([
        expect.objectContaining({ path: "version" }),
      ]),
    });
  });
});

describe("recordedCallFingerprint", () => {
  it("hashes the action and arguments deterministically", async () => {
    const recorder = new ReplayRecorder();
    const call = recorder.record({
      action: "math.add",
      args: { a: 1, b: 2 },
      principalId: "user_1",
      durationMs: 1,
    });

    const first = await recordedCallFingerprint(call);
    const second = await recordedCallFingerprint({
      ...call,
      id: "call_other",
      timestamp: new Date(0).toISOString(),
    });

    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
  });
});
