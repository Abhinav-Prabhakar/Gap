import type { EvalCase, EvalReport, EvalReportJSON, EvalResult, RunEvalsOptions, ToolChoice } from "./types";
import type { ConfusionMatrix } from "./types";
import { scoreArgs } from "./args";

const NONE = "(none)";

function formatPercent(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}

function caseLabel(evalCase: EvalCase): string {
  const name = evalCase.name?.trim();
  return name && name.length > 0 ? name : evalCase.prompt;
}

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "Planner failed.";
}

/** Guard a planner's runtime output, treating unusable values as "no tool". */
function normalizeChoice(raw: unknown): ToolChoice {
  if (typeof raw !== "object" || raw === null) return { tool: null };
  const record = raw as Record<string, unknown>;
  const tool =
    typeof record.tool === "string" && record.tool.trim() !== "" ? record.tool : null;
  const choice: ToolChoice = { tool };
  if ("args" in record) choice.args = record.args;
  if (typeof record.reasoning === "string") choice.reasoning = record.reasoning;
  return choice;
}

/**
 * Run eval cases sequentially and score the planner's choices.
 *
 * Only tools visible to the supplied scopes are passed to the planner. Each
 * case is isolated: a planner error marks that case failed and the run
 * continues. Scoring uses subset argument matching and treats any forbidden
 * choice as a failure regardless of expectations.
 */
export async function runEvals(options: RunEvalsOptions): Promise<EvalReport> {
  const scopes = options.scopes ?? ["*"];
  const tools = options.registry.toToolDescriptors({ scopes: [...scopes] });
  const results: EvalResult[] = [];

  for (const [index, evalCase] of options.cases.entries()) {
    let choice: ToolChoice = { tool: null };
    let error: string | undefined;

    try {
      const raw = await options.planner.choose({
        prompt: evalCase.prompt,
        tools,
        ...(options.system === undefined ? {} : { system: options.system }),
      });
      choice = normalizeChoice(raw);
    } catch (caught) {
      error = describeError(caught);
    }

    const forbidden =
      choice.tool !== null && (evalCase.forbiddenTools?.includes(choice.tool) ?? false);
    const toolPassed =
      error === undefined && choice.tool === evalCase.expectedTool && !forbidden;
    const args = error
      ? { passed: false, missingArgs: [], extraArgs: [] }
      : scoreArgs(evalCase.expectedArgs, choice.args);
    const passed = error === undefined && toolPassed && args.passed;

    results.push({
      index,
      case: evalCase,
      choice,
      passed,
      toolPassed,
      argsPassed: args.passed,
      forbidden,
      missingArgs: [...args.missingArgs],
      extraArgs: [...args.extraArgs],
      ...(error === undefined ? {} : { error }),
    });
  }

  const passed = results.filter((result) => result.passed).length;
  return new EvalReportImpl(results.length, passed, results, buildConfusion(options.cases, results));
}

function buildConfusion(cases: readonly EvalCase[], results: readonly EvalResult[]): ConfusionMatrix {
  const rows = [...new Set(cases.map((evalCase) => evalCase.expectedTool))].sort((left, right) =>
    left.localeCompare(right),
  );

  const chosen = new Set<string>();
  let sawNone = false;
  for (const result of results) {
    if (result.choice.tool === null) sawNone = true;
    else chosen.add(result.choice.tool);
  }
  const columns = [...chosen].sort((left, right) => left.localeCompare(right));
  if (sawNone) columns.push(NONE);

  const counts: Record<string, Record<string, number>> = {};
  for (const row of rows) {
    const cells: Record<string, number> = {};
    for (const column of columns) cells[column] = 0;
    counts[row] = cells;
  }

  for (const result of results) {
    const row = counts[result.case.expectedTool];
    if (!row) continue;
    const column = result.choice.tool ?? NONE;
    row[column] = (row[column] ?? 0) + 1;
  }

  return { rows, columns, counts };
}

function truncate(value: string, limit: number): string {
  const singleLine = value.replace(/\s+/g, " ").trim();
  if (singleLine.length <= limit) return singleLine;
  return `${singleLine.slice(0, Math.max(0, limit - 3))}...`;
}

function pad(value: string, width: number): string {
  return value.length >= width ? value : `${value}${" ".repeat(width - value.length)}`;
}

function resultDetail(result: EvalResult): string {
  if (result.error !== undefined) return `error: ${result.error}`;
  if (result.forbidden) return `forbidden tool: ${result.choice.tool ?? NONE}`;
  if (!result.toolPassed) {
    return `tool: ${result.choice.tool ?? NONE} != ${result.case.expectedTool}`;
  }
  if (!result.argsPassed) {
    const parts: string[] = [];
    if (result.missingArgs.length > 0) {
      parts.push(`missing: ${result.missingArgs.join(", ")}`);
    }
    if (result.extraArgs.length > 0) {
      parts.push(`extra: ${result.extraArgs.join(", ")}`);
    }
    return parts.join("; ");
  }
  return result.extraArgs.length > 0 ? `extra args: ${result.extraArgs.join(", ")}` : "";
}

function renderTable(headers: readonly string[], rows: readonly string[][], limits: readonly number[]): string {
  const prepared = rows.map((row) =>
    row.map((cell, index) => truncate(cell, limits[index] ?? Number.POSITIVE_INFINITY)),
  );
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...prepared.map((row) => row[index]?.length ?? 0)),
  );
  const render = (row: readonly string[]): string =>
    row.map((cell, index) => pad(cell, widths[index] ?? 0)).join("  ").trimEnd();

  return [
    render(headers),
    render(widths.map((width) => "-".repeat(width))),
    ...prepared.map(render),
  ].join("\n");
}

function renderConfusion(confusion: ConfusionMatrix): string {
  if (confusion.rows.length === 0) return "No cases ran.";
  if (confusion.columns.length === 0) return "";
  const headers = ["Expected \\ Chosen", ...confusion.columns];
  const rows = confusion.rows.map((row) => [
    row,
    ...confusion.columns.map((column) => String(confusion.counts[row]?.[column] ?? 0)),
  ]);
  return renderTable(headers, rows, [40, ...confusion.columns.map(() => 16)]);
}

class EvalReportImpl implements EvalReport {
  constructor(
    readonly total: number,
    readonly passed: number,
    readonly results: EvalResult[],
    readonly confusion: ConfusionMatrix,
  ) {}

  get passRate(): number {
    return this.total === 0 ? 0 : this.passed / this.total;
  }

  summary(): string {
    if (this.total === 0) return "Tool-selection evals: no cases ran.";

    const results = this.results.map((result) => [
      String(result.index + 1),
      caseLabel(result.case),
      result.case.expectedTool,
      result.choice.tool ?? NONE,
      result.passed ? "PASS" : "FAIL",
      resultDetail(result),
    ]);

    return [
      `Tool-selection evals: ${this.passed}/${this.total} passed (${formatPercent(this.passRate)})`,
      "",
      renderTable(["#", "Case", "Expected", "Chosen", "Result", "Details"], results, [
        4, 32, 28, 28, 6, 56,
      ]),
      "",
      "Confusion matrix (rows = expected, columns = chosen):",
      renderConfusion(this.confusion),
    ].join("\n");
  }

  toJSON(): string {
    const data: EvalReportJSON = {
      total: this.total,
      passed: this.passed,
      passRate: this.passRate,
      results: this.results,
      confusion: this.confusion,
    };
    return JSON.stringify(data, null, 2);
  }
}

/** Render the compact human-readable summary of an eval report. */
export function formatEvalReport(report: EvalReport): string {
  return report.summary();
}

function markdownCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
}

/**
 * Render an eval report as Markdown, suitable for a PR comment, job summary
 * or checked-in report. No ANSI codes are used.
 */
export function reportToMarkdown(report: EvalReport): string {
  const lines: string[] = [
    "# Tool-selection evals",
    "",
    `**${report.passed} / ${report.total} passed (${formatPercent(report.passRate)})**`,
    "",
  ];

  if (report.results.length === 0) {
    lines.push("No cases ran.");
    return lines.join("\n");
  }

  lines.push("| # | Case | Expected | Chosen | Result | Details |");
  lines.push("| ---: | --- | --- | --- | --- | --- |");
  for (const result of report.results) {
    lines.push(
      `| ${result.index + 1} | ${markdownCell(caseLabel(result.case))} | ` +
        `${markdownCell(result.case.expectedTool)} | ${markdownCell(result.choice.tool ?? NONE)} | ` +
        `${result.passed ? "PASS" : "FAIL"} | ${markdownCell(resultDetail(result))} |`,
    );
  }

  lines.push("", "## Confusion matrix", "");
  const headers = ["Expected \\ Chosen", ...report.confusion.columns];
  lines.push(`| ${headers.map(markdownCell).join(" | ")} |`);
  lines.push(`| --- | ${report.confusion.columns.map(() => "---:").join(" | ")} |`);
  for (const row of report.confusion.rows) {
    const cells = report.confusion.columns.map(
      (column) => String(report.confusion.counts[row]?.[column] ?? 0),
    );
    lines.push(`| ${markdownCell(row)} | ${cells.join(" | ")} |`);
  }

  return lines.join("\n");
}
