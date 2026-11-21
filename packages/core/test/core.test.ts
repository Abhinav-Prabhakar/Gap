import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  ActionRegistry,
  GapError,
  canonicalJson,
  defineAction,
  hasScopes,
  hashValue,
  missingScopes,
  normalizeError,
  parseValue,
  redact,
  schemaPathsWithoutDescriptions,
  toInputJsonSchema,
  toToolDescriptor,
  validateValue,
} from "../src/index";

const echo = defineAction({
  name: "test.echo",
  description: "Echo a message back to the caller. Pure and side-effect free.",
  input: z.object({ message: z.string().min(1).describe("Message to echo.") }),
  output: z.object({ message: z.string() }),
  tags: ["read-only"],
  execute: ({ message }) => ({ message }),
});

describe("action contract", () => {
  it("infers the handler input from the Zod schema", () => {
    const result = echo.execute({ message: "hi" }, {} as never);
    expect(result).toEqual({ message: "hi" });
  });

  it("rejects invalid names at registration", () => {
    const bad = defineAction({
      name: "not a valid name!",
      description: "This is an intentionally invalid action used by tests.",
      execute: () => null,
    });
    expect(() => new ActionRegistry([bad])).toThrow(GapError);
  });

  it("rejects duplicate actions", () => {
    const registry = new ActionRegistry([echo]);
    expect(() => registry.add(echo)).toThrow(/already registered/);
  });

  it("filters tools by scope", () => {
    const privateAction = defineAction({
      name: "billing.charge",
      description: "Charge a customer's stored payment method for an invoice.",
      scopes: ["billing:write"],
      execute: () => ({ ok: true }),
    });
    const registry = new ActionRegistry([echo, privateAction]);
    expect(registry.visibleTo(["read"]).map((a) => a.name)).toEqual(["test.echo"]);
    expect(registry.visibleTo(["billing:*"]).map((a) => a.name)).toEqual([
      "billing.charge",
      "test.echo",
    ]);
  });

  it("builds MCP descriptors with structured annotations", () => {
    const descriptor = toToolDescriptor(echo);
    expect(descriptor.name).toBe("test.echo");
    expect(descriptor.inputSchema.type).toBe("object");
    expect(descriptor.annotations?.readOnlyHint).toBe(true);
    expect(descriptor._meta?.["gap/risk"]).toBe("low");
  });

  it("warns about destructive actions without confirmation", () => {
    const danger = defineAction({
      name: "invoices.delete",
      description: "Permanently delete an invoice and all of its line items.",
      risk: "critical",
      execute: () => null,
    });
    const issues = new ActionRegistry([danger]).validate();
    expect(issues.some((issue) => issue.code === "destructive.no_confirmation")).toBe(true);
    expect(issues.some((issue) => issue.code === "risk.no_confirmation")).toBe(true);
  });
});

describe("schema conversion and validation", () => {
  it("converts Zod to clean JSON Schema", () => {
    const schema = z.object({
      name: z.string().describe("Customer name."),
      count: z.number().int().default(3),
      tags: z.array(z.string()).optional(),
    });
    const json = toInputJsonSchema(schema);
    expect(json.$schema).toBeUndefined();
    expect(json.type).toBe("object");
    expect((json.required as string[]).sort()).toEqual(["name"]);
    expect(schemaPathsWithoutDescriptions(json)).toEqual(["count", "tags"]);
  });

  it("validates Zod input with readable paths", () => {
    const schema = z.object({ nested: z.object({ age: z.number().min(18) }) });
    const result = validateValue(schema, { nested: { age: 12 } });
    expect(result.success).toBe(false);
    if (!result.success) expect(result.issues[0]?.path).toBe("nested.age");
  });

  it("validates plain JSON Schema input", () => {
    const schema = {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    };
    expect(validateValue(schema, { id: "x" }).success).toBe(true);
    const failed = validateValue(schema, { id: 4 });
    expect(failed.success).toBe(false);
  });

  it("throws a structured invalid input error", () => {
    try {
      parseValue(z.object({ id: z.string() }), {});
      throw new Error("should not reach");
    } catch (error) {
      expect(error).toBeInstanceOf(GapError);
      expect((error as GapError).code).toBe("INVALID_INPUT");
    }
  });
});

describe("identity and redaction helpers", () => {
  it("matches wildcard scopes", () => {
    expect(hasScopes(["invoices:*"], ["invoices:read", "invoices:write"])).toBe(true);
    expect(hasScopes(["*"], ["anything"])).toBe(true);
    expect(hasScopes(["invoices:read"], ["invoices:write"])).toBe(false);
    expect(missingScopes(["invoices:read"], ["invoices:read", "invoices:write"])).toEqual([
      "invoices:write",
    ]);
  });

  it("redacts nested and array paths without mutating", () => {
    const source = {
      customer: { name: "Ada", ssn: "123" },
      items: [{ ssn: "1", sku: "a" }, { ssn: "2", sku: "b" }],
    };
    const output = redact(source, ["customer.ssn", "items[].ssn"]);
    expect(output.customer.ssn).toBe("[REDACTED]");
    expect(output.items[0]?.ssn).toBe("[REDACTED]");
    expect(source.customer.ssn).toBe("123");
  });

  it("canonicalizes object keys and hashes deterministically", async () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
    const one = await hashValue({ b: 1, a: 2 });
    const two = await hashValue({ a: 2, b: 1 });
    expect(one).toBe(two);
    expect(one).toHaveLength(64);
  });

  it("normalizes unknown errors to opaque internal errors", () => {
    const error = normalizeError(new Error("database password leaked"));
    expect(error.code).toBe("INTERNAL");
    expect(error.expose).toBe(false);
  });
});
