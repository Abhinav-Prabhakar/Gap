import { describe, expect, it } from "vitest";
import { ActionRegistry } from "gapmcp-core";
import { estimateDescriptionTokens, findAmbiguousTools, lintRegistry } from "../src/index";
import { tool } from "./helpers";

describe("estimateDescriptionTokens", () => {
  it("estimates words times 1.3, rounded", () => {
    expect(estimateDescriptionTokens("one two three four five six seven eight nine ten")).toBe(13);
    expect(estimateDescriptionTokens("   ")).toBe(0);
    expect(estimateDescriptionTokens("create")).toBe(1);
  });
});

describe("lintRegistry", () => {
  it("scores a clean registry 100", () => {
    const registry = new ActionRegistry([
      tool("invoices.list", "Returns a paginated list of invoices for the current tenant.", {
        readOnly: true,
      }),
      tool("invoices.create", "Creates a new invoice and returns its identifier and totals."),
    ]);

    const report = lintRegistry(registry);

    expect(report.issues).toEqual([]);
    expect(report.ambiguous).toEqual([]);
    expect(report.score).toBe(100);
  });

  it("detects ambiguous sibling tools and records one sorted pair", () => {
    const registry = new ActionRegistry([
      tool(
        "invoices.list",
        "Returns a paginated list of invoices for the current tenant with filtering.",
        { readOnly: true },
      ),
      tool(
        "invoices.search",
        "Returns a paginated list of invoices for the current tenant with search filtering.",
        { readOnly: true },
      ),
    ]);

    const report = lintRegistry(registry);

    expect(report.ambiguous).toEqual([["invoices.list", "invoices.search"]]);
    expect(report.issues.some((issue) => issue.code === "description.ambiguous")).toBe(true);
    expect(report.score).toBe(95);
  });

  it("returns every unique pair in sorted order for a similar trio", () => {
    const description =
      "Returns a paginated list of invoices for the current tenant with filtering and sorting.";
    const registry = new ActionRegistry([
      tool("invoices.list", description, { readOnly: true }),
      tool("invoices.search", description, { readOnly: true }),
      tool("invoices.find", description, { readOnly: true }),
    ]);

    expect(findAmbiguousTools(registry)).toEqual([
      ["invoices.find", "invoices.list"],
      ["invoices.find", "invoices.search"],
      ["invoices.list", "invoices.search"],
    ]);
  });

  it("warns about descriptions over the token budget", () => {
    const words = Array.from({ length: 100 }, (_, index) => `entry${index}`);
    const registry = new ActionRegistry([
      tool("reports.export", `Returns ${words.join(" ")}`, { readOnly: true }),
    ]);

    const report = lintRegistry(registry);
    const issue = report.issues.find((candidate) => candidate.code === "description.tokens");

    expect(issue).toMatchObject({ level: "warn", action: "reports.export" });
    expect(issue?.message).toContain("131 tokens");
    expect(report.ambiguous).toEqual([]);
    expect(report.score).toBe(95);
  });

  it("warns when a mutating description has no outcome word", () => {
    const registry = new ActionRegistry([
      tool("invoices.update", "Handles invoice documents in a careful and reliable manner."),
    ]);

    const report = lintRegistry(registry);
    const issue = report.issues.find((candidate) => candidate.code === "description.no_outcome");

    expect(issue).toMatchObject({ level: "warn", action: "invoices.update" });
    expect(report.score).toBe(95);
  });

  it("does not warn about outcomes for tools marked read-only", () => {
    const registry = new ActionRegistry([
      tool("invoices.read", "Fetches invoice documents for the current tenant.", {
        readOnly: true,
      }),
    ]);

    const report = lintRegistry(registry);
    expect(report.issues.some((issue) => issue.code === "description.no_outcome")).toBe(false);
    expect(report.ambiguous).toEqual([]);
  });

  it("lowers the score for core validation errors", () => {
    const registry = new ActionRegistry([tool("invoices.update", "", { readOnly: true })]);

    const report = lintRegistry(registry);
    const error = report.issues.find((issue) => issue.level === "error");

    expect(error?.code).toBe("description.missing");
    expect(report.score).toBe(80);
  });

  it("floors the score at zero", () => {
    const names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] as const;
    const registry = new ActionRegistry(
      names.map((name) => tool(`${name}.run`, "", { readOnly: true })),
    );

    const report = lintRegistry(registry);
    expect(report.issues.filter((issue) => issue.level === "error").length).toBe(6);
    expect(report.score).toBe(0);
  });
});
