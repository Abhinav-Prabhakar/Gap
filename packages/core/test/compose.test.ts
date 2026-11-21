import { describe, expect, it } from "vitest";
import { z } from "zod";
import { ActionRegistry, defineAction, defineSkill, searchActions, silentLogger, type ActionContext } from "../src/index";

function ctx(overrides: Partial<ActionContext> = {}): ActionContext {
  return {
    principal: { id: "usr_test", scopes: ["*"] },
    scopes: ["*"],
    dryRun: false,
    signal: AbortSignal.timeout(5000),
    traceId: "trace_test",
    logger: silentLogger,
    ...overrides,
  };
}

const listCustomers = defineAction({
  name: "customers.list",
  description: "List customers, optionally filtered by a name query. Read-only.",
  input: z.object({ query: z.string().optional() }),
  output: z.object({ customers: z.array(z.string()) }),
  scopes: ["customers:read"],
  execute: ({ query }) => ({ customers: ["Ada", "Grace"].filter((name) => !query || name.includes(query)) }),
});

const createInvoice = defineAction({
  name: "invoices.create",
  description: "Create a draft invoice for a customer. Does not send it.",
  input: z.object({ customer: z.string() }),
  output: z.object({ id: z.string() }),
  scopes: ["invoices:write"],
  execute: ({ customer }, ctx) => ({ id: `inv_${customer}_${ctx.dryRun ? "dry" : "live"}` }),
});

const invoiceCustomer = defineSkill({
  name: "customers.invoice",
  description: "Find a customer by name and create a draft invoice for them in one step.",
  input: z.object({ customer: z.string() }),
  output: z.object({ id: z.string(), customer: z.string() }),
  uses: [listCustomers, createInvoice],
  async execute({ customer }, _ctx, run) {
    const found = await run<{ customers: string[] }>(listCustomers, { query: customer });
    const match = found.customers[0];
    if (!match) throw new Error("Customer not found.");
    const invoice = await run<{ id: string }>(createInvoice, { customer: match });
    return { id: invoice.id, customer: match };
  },
});

describe("compound skills", () => {
  it("unions the scopes of composed actions", () => {
    expect(invoiceCustomer.scopes).toEqual(["customers:read", "invoices:write"]);
    expect(invoiceCustomer.risk).toBe("medium");
  });

  it("runs child actions with validated input and the same context", async () => {
    await expect(invoiceCustomer.execute({ customer: "Ada" }, ctx({ dryRun: true }))).resolves.toEqual({
      id: "inv_Ada_dry",
      customer: "Ada",
    });
  });
});

describe("tool search", () => {
  const registry = new ActionRegistry([listCustomers, createInvoice, invoiceCustomer]);

  it("ranks name matches above description matches", () => {
    const results = searchActions(registry, "invoice");
    expect(results[0]?.action.name).toBe("customers.invoice");
    expect(results.map((item) => item.action.name)).toContain("invoices.create");
  });

  it("filters by scope", () => {
    const results = searchActions(registry, "invoice", { scopes: ["customers:read", "invoices:write"] });
    expect(results.map((item) => item.action.name)).toEqual(["customers.invoice", "invoices.create"]);
  });

  it("respects the limit and empty queries", () => {
    expect(searchActions(registry, "invoice", { limit: 1 })).toHaveLength(1);
    expect(searchActions(registry, "   ")).toEqual([]);
  });
});
