import { describe, expect, it } from "vitest";
import { GapError, defineAction, silentLogger } from "gapmcp-core";
import type { ActionContext, AnyAction, PolicyDecision } from "gapmcp-core";
import type { PolicyDocument } from "../src/index";
import { GapPolicy, definePolicy, parsePolicy } from "../src/index";

const TEST_DESCRIPTION = "Test action used by the policy engine unit tests.";

function makeAction(name: string): AnyAction {
  return defineAction({
    name,
    description: TEST_DESCRIPTION,
    execute: () => ({ ok: true }),
  });
}

function makeContext(overrides: Partial<ActionContext> = {}): ActionContext {
  return {
    principal: { id: "user_1", scopes: ["*"] },
    scopes: ["*"],
    dryRun: false,
    signal: new AbortController().signal,
    traceId: "trace_test",
    logger: silentLogger,
    ...overrides,
  };
}

function decide(
  document: PolicyDocument,
  tool: string,
  args: unknown = {},
  overrides: Partial<ActionContext> = {},
): { decision: PolicyDecision; ctx: ActionContext } {
  const ctx = makeContext(overrides);
  const policy = new GapPolicy(document);
  const decision = policy.evaluate({
    action: makeAction(tool),
    args,
    ctx,
  });
  return { decision, ctx };
}

function captureGapError(run: () => unknown): GapError {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(GapError);
    return error as GapError;
  }
  throw new Error("Expected the call to throw a GapError.");
}

describe("tool matching", () => {
  it("matches an exact tool name", () => {
    const policy = definePolicy({
      version: 1,
      rules: [
        {
          tools: ["invoices.delete"],
          deny: true,
          reason: "Invoices cannot be deleted.",
        },
      ],
    });

    expect(decide(policy, "invoices.delete").decision).toEqual({
      decision: "deny",
      code: "POLICY_DENIED",
      reason: "Invoices cannot be deleted.",
    });
    expect(decide(policy, "invoices.list").decision).toEqual({ decision: "allow" });
  });

  it("matches namespace globs without matching the namespace itself", () => {
    const policy = definePolicy({
      version: 1,
      rules: [{ tools: ["invoices.*"], deny: true }],
    });

    expect(decide(policy, "invoices.create").decision.decision).toBe("deny");
    expect(decide(policy, "invoices.create.draft").decision.decision).toBe("deny");
    expect(decide(policy, "invoices").decision.decision).toBe("allow");
    expect(decide(policy, "billing.charge").decision.decision).toBe("allow");
  });

  it("matches the global wildcard", () => {
    const policy = definePolicy({
      version: 1,
      rules: [{ tools: ["*"], deny: true, reason: "Locked down." }],
    });

    expect(decide(policy, "anything.at.all").decision).toMatchObject({
      decision: "deny",
      reason: "Locked down.",
    });
  });

  it("treats a rule without tools as applying to every tool", () => {
    const policy = definePolicy({
      version: 1,
      rules: [{ redact: ["customer.email"] }],
    });

    expect(decide(policy, "invoices.list").decision.redactPaths).toEqual([
      "customer.email",
    ]);
  });
});

describe("defaults and precedence", () => {
  it("denies unmatched tools when the document defaults to deny", () => {
    const policy = definePolicy({
      version: 1,
      default: "deny",
      rules: [{ tools: ["reports.read"] }],
    });

    expect(decide(policy, "reports.read").decision.decision).toBe("allow");
    expect(decide(policy, "reports.write").decision).toEqual({
      decision: "deny",
      code: "POLICY_DENIED",
      reason: "Denied by default policy.",
    });
  });

  it("treats deny:false as an explicit allow under a deny default", () => {
    const policy = definePolicy({
      version: 1,
      default: "deny",
      rules: [{ tools: ["invoices.create"], deny: false }],
    });

    expect(decide(policy, "invoices.create").decision.decision).toBe("allow");
    expect(decide(policy, "invoices.delete").decision.decision).toBe("deny");
  });

  it("gives any matching deny precedence over confirms and allows", () => {
    const policy = definePolicy({
      version: 1,
      rules: [
        { tools: ["payments.*"], confirm: true, reason: "Review payment." },
        { tools: ["*"], deny: false },
        { tools: ["payments.charge"], deny: true, reason: "Charges blocked." },
      ],
    });

    expect(decide(policy, "payments.charge").decision).toEqual({
      decision: "deny",
      code: "POLICY_DENIED",
      reason: "Charges blocked.",
    });
    expect(decide(policy, "invoices.create").decision).toEqual({ decision: "allow" });
  });

  it("confirms when any matching rule confirms", () => {
    const policy = definePolicy({
      version: 1,
      rules: [
        { tools: ["invoices.*"], confirm: true, reason: "Review the invoice." },
        { tools: ["invoices.delete"], deny: false },
      ],
    });

    expect(decide(policy, "invoices.delete").decision).toEqual({
      decision: "confirm",
      reason: "Review the invoice.",
    });
  });

  it("honours document-level deny and confirm lists", () => {
    const policy = definePolicy({
      version: 1,
      deny: ["admin.*"],
      confirm: ["invoices.send"],
      rules: [{ tools: ["invoices.send"], deny: false }],
    });

    expect(decide(policy, "admin.reset").decision).toEqual({
      decision: "deny",
      code: "POLICY_DENIED",
      reason: "Denied by the policy document.",
    });
    expect(decide(policy, "invoices.send").decision).toEqual({
      decision: "confirm",
      reason: "Confirmation required by the policy document.",
    });
  });
});

describe("limits", () => {
  it("denies a nested amount above the limit with metadata", () => {
    const policy = definePolicy({
      version: 1,
      rules: [
        {
          tools: ["payments.charge"],
          maxAmount: 1000,
          reason: "Charge limit exceeded.",
        },
      ],
    });

    expect(
      decide(policy, "payments.charge", {
        invoice: { total: 1200, currency: "usd" },
      }).decision,
    ).toEqual({
      decision: "deny",
      code: "LIMIT_EXCEEDED",
      reason: "Charge limit exceeded.",
      metadata: { limit: 1000, path: "invoice.total", value: 1200 },
    });
  });

  it("denies the first amount above the limit inside nested arrays", () => {
    const policy = definePolicy({
      version: 1,
      rules: [{ tools: ["orders.create"], maxAmount: 500 }],
    });

    const { decision } = decide(policy, "orders.create", {
      order: { lines: [{ amount: 100 }, { amount: 2500 }] },
    });

    expect(decision).toMatchObject({
      decision: "deny",
      code: "LIMIT_EXCEEDED",
      metadata: { limit: 500, path: "order.lines[1].amount", value: 2500 },
    });
    expect(decision.reason).toContain("order.lines[1].amount");
  });

  it("allows amounts exactly at or below the limit", () => {
    const policy = definePolicy({
      version: 1,
      rules: [{ tools: ["payments.charge"], maxAmount: 1000 }],
    });

    expect(decide(policy, "payments.charge", { total: 1000 }).decision).toEqual({
      decision: "allow",
    });
  });

  it("accepts a custom amount path and ignores other numeric keys", () => {
    const policy = definePolicy({
      version: 1,
      rules: [
        {
          tools: ["payments.charge"],
          maxAmount: 50,
          amountPaths: ["charge.amount"],
        },
      ],
    });

    expect(
      decide(policy, "payments.charge", {
        charge: { amount: 75 },
        total: 999999,
      }).decision,
    ).toMatchObject({
      decision: "deny",
      code: "LIMIT_EXCEEDED",
      metadata: { limit: 50, path: "charge.amount", value: 75 },
    });
  });

  it("supports wildcard amount paths through arrays", () => {
    const policy = definePolicy({
      version: 1,
      rules: [
        {
          tools: ["payments.batch"],
          maxAmount: 50,
          amountPaths: ["payments[].amount"],
        },
      ],
    });

    expect(
      decide(policy, "payments.batch", {
        payments: [{ amount: 10 }, { amount: 60 }],
      }).decision,
    ).toMatchObject({
      decision: "deny",
      code: "LIMIT_EXCEEDED",
      metadata: { limit: 50, path: "payments[].amount", value: 60 },
    });
  });

  it("checks every array recursively by default", () => {
    const policy = definePolicy({
      version: 1,
      rules: [{ tools: ["orders.create"], maxArrayLength: 2 }],
    });

    expect(
      decide(policy, "orders.create", {
        order: { lines: [{ sku: "a" }, { sku: "b" }, { sku: "c" }] },
      }).decision,
    ).toEqual({
      decision: "deny",
      code: "LIMIT_EXCEEDED",
      reason: 'Array at "order.lines" has 3 items, exceeding the max length of 2.',
      metadata: { limit: 2, path: "order.lines", value: 3 },
    });
  });

  it("restricts array checks to custom array paths", () => {
    const policy = definePolicy({
      version: 1,
      rules: [
        {
          tools: ["articles.update"],
          maxArrayLength: 3,
          arrayPaths: ["tags"],
        },
      ],
    });

    expect(
      decide(policy, "articles.update", {
        tags: ["a", "b", "c", "d"],
        related: [1, 2, 3, 4, 5],
      }).decision,
    ).toMatchObject({
      decision: "deny",
      code: "LIMIT_EXCEEDED",
      metadata: { limit: 3, path: "tags", value: 4 },
    });
  });

  it("does not throw for limit violations", () => {
    const policy = definePolicy({
      version: 1,
      rules: [{ tools: ["*"], maxAmount: 1 }],
    });

    expect(() =>
      decide(policy, "payments.charge", { total: 2 }),
    ).not.toThrow();
  });
});

describe("redaction and dry runs", () => {
  it("merges redactions from every matching rule and the document", () => {
    const policy = definePolicy({
      version: 1,
      redact: ["args.password"],
      rules: [
        { tools: ["users.*"], redact: ["args.card.number"] },
        {
          tools: ["users.update"],
          redact: ["args.card.number", "args.ssn"],
        },
      ],
    });

    expect(decide(policy, "users.update").decision.redactPaths).toEqual([
      "args.password",
      "args.card.number",
      "args.ssn",
    ]);
    expect(decide(policy, "invoices.update").decision.redactPaths).toEqual([
      "args.password",
    ]);
  });

  it("sets ctx.dryRun and reflects it in metadata", () => {
    const policy = definePolicy({
      version: 1,
      rules: [{ tools: ["reports.run"], dryRun: true }],
    });

    const { decision, ctx } = decide(policy, "reports.run");

    expect(decision).toEqual({ decision: "allow", metadata: { dryRun: true } });
    expect(ctx.dryRun).toBe(true);
  });

  it("lets a dry-run rule allow a tool under a deny default", () => {
    const policy = definePolicy({
      version: 1,
      default: "deny",
      rules: [{ tools: ["reports.preview"], dryRun: true }],
    });

    const { decision, ctx } = decide(policy, "reports.preview");

    expect(decision.decision).toBe("allow");
    expect(decision.metadata).toEqual({ dryRun: true });
    expect(ctx.dryRun).toBe(true);
  });

  it("leaves ctx.dryRun untouched when no matching rule asks for it", () => {
    const policy = definePolicy({ version: 1, rules: [] });
    const { ctx } = decide(policy, "reports.run");
    expect(ctx.dryRun).toBe(false);
  });
});

describe("scope-gated rules", () => {
  it("skips rules whose scopes the caller does not hold", () => {
    const policy = definePolicy({
      version: 1,
      rules: [
        {
          tools: ["billing.*"],
          scopes: ["billing:write"],
          deny: true,
          reason: "Billing write access is suspended.",
        },
      ],
    });

    const readOnly = decide(policy, "billing.charge", {}, {
      scopes: ["billing:read"],
      principal: { id: "user_1", scopes: ["billing:read"] },
    });
    expect(readOnly.decision.decision).toBe("allow");

    const writer = decide(policy, "billing.charge", {}, {
      scopes: ["billing:write"],
      principal: { id: "user_1", scopes: ["billing:write"] },
    });
    expect(writer.decision.decision).toBe("deny");

    const wildcard = decide(policy, "billing.charge", {}, {
      scopes: ["billing:*"],
      principal: { id: "user_1", scopes: ["billing:*"] },
    });
    expect(wildcard.decision.decision).toBe("deny");
  });
});

describe("parsing and validation", () => {
  it("parses a JSON policy and evaluates it", () => {
    const parsed = parsePolicy(
      JSON.stringify({
        version: 1,
        default: "deny",
        rules: [{ tools: ["invoices.*"], confirm: true }],
        redact: ["customer.email"],
      }),
    );

    expect(parsed).toEqual({
      version: 1,
      default: "deny",
      rules: [{ tools: ["invoices.*"], confirm: true }],
      redact: ["customer.email"],
    });

    expect(decide(parsed, "invoices.send").decision).toEqual({
      decision: "confirm",
      reason: "Confirmation required by policy.",
      redactPaths: ["customer.email"],
    });
  });

  it("returns the original object from definePolicy after validating it", () => {
    const document: PolicyDocument = { version: 1, rules: [] };
    expect(definePolicy(document)).toBe(document);
  });

  it("rejects malformed JSON with an INVALID_INPUT GapError", () => {
    const error = captureGapError(() => parsePolicy("{ not json"));
    expect(error.code).toBe("INVALID_INPUT");
    expect(error.details).toMatchObject({ issues: expect.any(Array) });
  });

  it("rejects an unsupported policy version with details", () => {
    const error = captureGapError(() =>
      parsePolicy({ version: 2, rules: [] } as unknown as PolicyDocument),
    );
    expect(error.code).toBe("INVALID_INPUT");
    expect(error.details).toMatchObject({
      issues: expect.arrayContaining([
        expect.objectContaining({ path: "version" }),
      ]),
    });
  });

  it("rejects rules with invalid field types", () => {
    const error = captureGapError(() =>
      new GapPolicy({
        version: 1,
        rules: [{ maxAmount: "10", maxArrayLength: -1 }],
      } as unknown as PolicyDocument),
    );

    expect(error.code).toBe("INVALID_INPUT");
    expect(error.details).toMatchObject({
      issues: expect.arrayContaining([
        expect.objectContaining({ path: "rules[0].maxAmount" }),
        expect.objectContaining({ path: "rules[0].maxArrayLength" }),
      ]),
    });
  });
});
