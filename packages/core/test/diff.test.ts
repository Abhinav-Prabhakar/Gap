import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineAction, diffRegistries } from "../src/index";

const base = (overrides: Record<string, unknown> = {}) =>
  defineAction({
    name: "invoices.create",
    description: "Create a draft invoice. Does not send it.",
    input: z.object({
      customerId: z.string().describe("Customer id."),
      total: z.number().describe("Total in USD."),
    }),
    scopes: ["invoices:write"],
    execute: () => ({ id: "inv_1" }),
    ...overrides,
  });

describe("registry contract diff", () => {
  it("accepts identical registries", () => {
    const diff = diffRegistries([base()], [base()]);
    expect(diff.compatible).toBe(true);
    expect(diff.breaking).toEqual([]);
  });

  it("flags removed actions", () => {
    const diff = diffRegistries([base()], []);
    expect(diff.removed).toEqual(["invoices.create"]);
    expect(diff.breaking[0]?.detail).toMatch(/removed/);
  });

  it("flags removed and newly required input fields", () => {
    const next = defineAction({
      name: "invoices.create",
      description: "Create a draft invoice. Does not send it.",
      input: z.object({
        customerId: z.string().describe("Customer id."),
        currency: z.string().describe("ISO currency."),
      }),
      scopes: ["invoices:write"],
      execute: () => ({ id: "inv_1" }),
    });
    const diff = diffRegistries([base()], [next]);
    expect(diff.breaking.some((change) => change.detail.includes('"total" was removed'))).toBe(true);
    expect(diff.breaking.some((change) => change.detail.includes('"currency" was added'))).toBe(true);
  });

  it("treats added scopes as breaking and removed scopes as compatible", () => {
    const stricter = base({ scopes: ["invoices:write", "billing:write"] });
    expect(diffRegistries([base()], [stricter]).breaking[0]?.detail).toMatch(/billing:write/);
    const looser = base({ scopes: [] });
    expect(diffRegistries([base()], [looser]).compatible).toBe(true);
  });

  it("reports description and risk changes without breaking", () => {
    const changed = base({ description: "Create a draft invoice for a customer, with line items.", risk: "high" });
    const diff = diffRegistries([base()], [changed]);
    expect(diff.compatible).toBe(true);
    expect(diff.changed.map((change) => change.kind).sort()).toEqual(["description", "risk"]);
  });

  it("marks new actions as compatible additions", () => {
    const extra = defineAction({
      name: "invoices.list",
      description: "List invoices. Read-only.",
      execute: () => [],
    });
    const diff = diffRegistries([base()], [base(), extra]);
    expect(diff.added).toEqual(["invoices.list"]);
    expect(diff.compatible).toBe(true);
  });
});
