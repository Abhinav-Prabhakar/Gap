import { describe, expect, it } from "vitest";
import { ActionRegistry } from "gapmcp-core";
import type { EvalCase, Planner, PlannerInput } from "../src/index";
import { MockPlanner, formatEvalReport, reportToMarkdown, runEvals } from "../src/index";
import { tool } from "./helpers";

const listDescription = "Returns a paginated list of invoices for the current tenant.";
const createDescription = "Creates a new invoice and returns its identifier and totals.";
const getDescription = "Returns one invoice by id for the current tenant.";
const searchDescription = "Searches invoices and returns matching records for the tenant.";

function registry(): ActionRegistry {
  return new ActionRegistry([
    tool("invoices.list", listDescription, { readOnly: true }),
    tool("invoices.create", createDescription),
    tool("invoices.get", getDescription, { readOnly: true }),
    tool("invoices.search", searchDescription, { readOnly: true }),
  ]);
}

describe("runEvals", () => {
  it("passes matching cases and reports extras without failing subset matches", async () => {
    const cases: EvalCase[] = [
      { name: "list invoices", prompt: "show me recent invoices", expectedTool: "invoices.list" },
      {
        name: "create invoice",
        prompt: "invoice Acme for 100",
        expectedTool: "invoices.create",
        expectedArgs: { customer: "Acme" },
      },
    ];
    const planner = new MockPlanner([
      { tool: "invoices.list" },
      { tool: "invoices.create", args: { customer: "Acme", total: 100 } },
    ]);

    const report = await runEvals({ registry: registry(), cases, planner });

    expect(report.total).toBe(2);
    expect(report.passed).toBe(2);
    expect(report.passRate).toBe(1);
    expect(report.results[0]?.toolPassed).toBe(true);
    expect(report.results[1]?.extraArgs).toEqual(["total"]);
    expect(report.results[1]?.passed).toBe(true);
  });

  it("fails on a tool mismatch and exposes the confusion cell", async () => {
    const report = await runEvals({
      registry: registry(),
      cases: [{ prompt: "show me invoices", expectedTool: "invoices.list" }],
      planner: new MockPlanner([{ tool: "invoices.search" }]),
    });

    const result = report.results[0];
    expect(result?.toolPassed).toBe(false);
    expect(result?.passed).toBe(false);
    expect(result?.argsPassed).toBe(true);
    expect(report.confusion.counts["invoices.list"]?.["invoices.search"]).toBe(1);
  });

  it("fails a case when the chosen tool is forbidden even if it matches", async () => {
    const report = await runEvals({
      registry: registry(),
      cases: [
        {
          prompt: "delete the invoice",
          expectedTool: "invoices.create",
          forbiddenTools: ["invoices.create"],
        },
      ],
      planner: new MockPlanner([{ tool: "invoices.create" }]),
    });

    const result = report.results[0];
    expect(result?.forbidden).toBe(true);
    expect(result?.toolPassed).toBe(true);
    expect(result?.passed).toBe(false);
  });

  it("reports missing arguments through the result", async () => {
    const report = await runEvals({
      registry: registry(),
      cases: [
        {
          prompt: "create an invoice for Acme on page 2",
          expectedTool: "invoices.create",
          expectedArgs: { customer: "Acme", page: 2 },
        },
      ],
      planner: new MockPlanner([{ tool: "invoices.create", args: { customer: "Acme" } }]),
    });

    const result = report.results[0];
    expect(result?.toolPassed).toBe(true);
    expect(result?.argsPassed).toBe(false);
    expect(result?.passed).toBe(false);
    expect(result?.missingArgs).toEqual(["page"]);
  });

  it("builds a sorted confusion matrix with all expected rows and a none column", async () => {
    const cases: EvalCase[] = [
      { prompt: "get", expectedTool: "invoices.get" },
      { prompt: "get again", expectedTool: "invoices.get" },
      { prompt: "search", expectedTool: "invoices.search" },
      { prompt: "list", expectedTool: "invoices.list" },
    ];
    const planner = new MockPlanner([
      { tool: "invoices.list" },
      { tool: "invoices.get" },
      { tool: null },
      { tool: "invoices.get" },
    ]);

    const report = await runEvals({ registry: registry(), cases, planner });

    expect(report.confusion.rows).toEqual([
      "invoices.get",
      "invoices.list",
      "invoices.search",
    ]);
    expect(report.confusion.columns).toEqual([
      "invoices.get",
      "invoices.list",
      "(none)",
    ]);
    expect(report.confusion.counts["invoices.get"]).toEqual({
      "invoices.get": 1,
      "invoices.list": 1,
      "(none)": 0,
    });
    expect(report.confusion.counts["invoices.list"]).toEqual({
      "invoices.get": 1,
      "invoices.list": 0,
      "(none)": 0,
    });
    expect(report.confusion.counts["invoices.search"]).toEqual({
      "invoices.get": 0,
      "invoices.list": 0,
      "(none)": 1,
    });
    expect(report.confusion.matrix).toEqual([
      [1, 1, 0],
      [1, 0, 0],
      [0, 0, 1],
    ]);
    expect(report.passed).toBe(1);
    expect(report.passRate).toBe(0.25);
  });

  it("renders a summary table and round-trips through JSON", async () => {
    const report = await runEvals({
      registry: registry(),
      cases: [
        { name: "list invoices", prompt: "show invoices", expectedTool: "invoices.list" },
        { name: "create invoice", prompt: "make one", expectedTool: "invoices.create" },
      ],
      planner: new MockPlanner([{ tool: "invoices.list" }, { tool: "invoices.list" }]),
    });

    const summary = report.summary();
    expect(summary).toContain("Expected");
    expect(summary).toContain("Chosen");
    expect(summary).toContain("PASS");
    expect(summary).toContain("FAIL");
    expect(summary).toContain("Confusion matrix");
    expect(formatEvalReport(report)).toBe(summary);

    const parsed = JSON.parse(report.toJSON()) as {
      total: number;
      passed: number;
      passRate: number;
      results: Array<{ case: EvalCase; passed: boolean }>;
      confusion: { rows: string[]; columns: string[] };
    };
    expect(parsed.total).toBe(2);
    expect(parsed.passed).toBe(1);
    expect(parsed.passRate).toBe(0.5);
    expect(parsed.results[1]?.case.prompt).toBe("make one");
    expect(parsed.results[1]?.passed).toBe(false);
    expect(parsed.confusion.rows).toEqual(["invoices.create", "invoices.list"]);

    const markdown = reportToMarkdown(report);
    expect(markdown).toContain("# Tool-selection evals");
    expect(markdown).toContain("FAIL");
  });

  it("captures a planner error per case and continues the run", async () => {
    let call = 0;
    const planner = new MockPlanner(() => {
      call += 1;
      if (call === 1) throw new Error("provider rate limited");
      return { tool: "invoices.list" };
    });
    const cases: EvalCase[] = [
      { prompt: "first", expectedTool: "invoices.list" },
      { prompt: "second", expectedTool: "invoices.list" },
    ];

    const report = await runEvals({ registry: registry(), cases, planner });

    expect(report.total).toBe(2);
    expect(report.passed).toBe(1);
    expect(report.results[0]?.error).toBe("provider rate limited");
    expect(report.results[0]?.choice.tool).toBeNull();
    expect(report.results[0]?.passed).toBe(false);
    expect(report.results[1]?.passed).toBe(true);
    expect(report.confusion.counts["invoices.list"]?.["(none)"]).toBe(1);
    expect(report.confusion.counts["invoices.list"]?.["invoices.list"]).toBe(1);
  });

  it("only passes tools visible to the requested scopes", async () => {
    const scoped = new ActionRegistry([
      tool("invoices.list", listDescription, {
        readOnly: true,
        scopes: ["invoices:read"],
      }),
      tool("invoices.create", createDescription, { scopes: ["invoices:write"] }),
    ]);
    const seen: string[][] = [];
    const planner: Planner = {
      async choose(input: PlannerInput) {
        seen.push(input.tools.map((descriptor) => descriptor.name));
        return { tool: "invoices.list" };
      },
    };

    const report = await runEvals({
      registry: scoped,
      cases: [{ prompt: "show invoices", expectedTool: "invoices.list" }],
      planner,
      scopes: ["invoices:read"],
    });

    expect(seen).toEqual([["invoices.list"]]);
    expect(report.passed).toBe(1);
  });

  it("calls the planner sequentially", async () => {
    let active = 0;
    let maxActive = 0;
    const planner: Planner = {
      async choose() {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await Promise.resolve();
        active -= 1;
        return { tool: "invoices.list" };
      },
    };

    await runEvals({
      registry: registry(),
      cases: [
        { prompt: "one", expectedTool: "invoices.list" },
        { prompt: "two", expectedTool: "invoices.list" },
        { prompt: "three", expectedTool: "invoices.list" },
      ],
      planner,
    });

    expect(maxActive).toBe(1);
  });

  it("reports a zero pass rate for an empty suite", async () => {
    const report = await runEvals({
      registry: registry(),
      cases: [],
      planner: new MockPlanner([]),
    });

    expect(report.total).toBe(0);
    expect(report.passRate).toBe(0);
    expect(report.summary()).toContain("no cases");
  });
});
