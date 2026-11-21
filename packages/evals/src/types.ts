import type { ActionRegistry, RegistryIssue, ToolDescriptor } from "gapmcp-core";

/**
 * The single decision a planner made for one prompt. `tool` is `null` when the
 * model deliberately answered without selecting a tool.
 */
export interface ToolChoice {
  /** The selected tool name, or `null` for "no tool". */
  tool: string | null;
  /** Raw arguments proposed for the tool. Not validated against the schema. */
  args?: unknown;
  /** Optional free-form explanation returned by the model. */
  reasoning?: string;
}

/** The deterministic input a {@link Planner} receives for one eval case. */
export interface PlannerInput {
  /** The user message under test. */
  prompt: string;
  /** Tools visible to the planner after scope filtering. */
  tools: ToolDescriptor[];
  /** Optional system prompt shared by every case. */
  system?: string;
}

/** Anything that can map a prompt and a tool catalog to one tool choice. */
export interface Planner {
  choose(input: PlannerInput): Promise<ToolChoice>;
}

/**
 * Responses accepted by {@link MockPlanner}: a fixed array consumed in order,
 * or a handler invoked for every call.
 */
export type MockPlannerResponses =
  | ToolChoice[]
  | ((input: PlannerInput) => ToolChoice | Promise<ToolChoice>);

/** Options for {@link httpPlanner}. */
export interface HttpPlannerOptions {
  /** OpenAI-compatible base URL or full `/chat/completions` URL. */
  endpoint: string;
  /** Model identifier sent in the request body. */
  model: string;
  /** Bearer token. Never included in error messages. */
  apiKey?: string;
  /** Extra request headers; names are matched case-insensitively. */
  headers?: Record<string, string>;
  /** Fetch implementation, useful for tests or non-standard runtimes. */
  fetch?: typeof fetch;
}

/** One tool-selection case. */
export interface EvalCase {
  /** Stable label for reports. Defaults to the prompt. */
  name?: string;
  /** The user message shown to the planner. */
  prompt: string;
  /** The tool the model should select. */
  expectedTool: string;
  /** Fields the selected arguments must contain (subset match). */
  expectedArgs?: Record<string, unknown>;
  /** Tools that must never be selected for this case. */
  forbiddenTools?: string[];
}

/** The scored outcome of one eval case. */
export interface EvalResult {
  /** Zero-based position in the case list. */
  index: number;
  /** The original case, including its expectation. */
  case: EvalCase;
  /** The planner's choice; `{ tool: null }` when it failed or selected nothing. */
  choice: ToolChoice;
  /** True only when the tool, arguments and forbidden-tool checks all pass. */
  passed: boolean;
  /** True when the chosen tool exactly equals `expectedTool`. */
  toolPassed: boolean;
  /** True when the provided arguments satisfy the expected subset. */
  argsPassed: boolean;
  /** True when the chosen tool appears in `forbiddenTools`. */
  forbidden: boolean;
  /** Expected paths that were absent or held a different value. */
  missingArgs: string[];
  /** Top-level argument keys that were not part of the expectation. */
  extraArgs: string[];
  /** Planner failure message, when the planner threw for this case. */
  error?: string;
}

/**
 * A confusion matrix with expected tools as rows and chosen tools as columns.
 * Counts are initialized to zero for every row/column pair. `(none)` is used
 * when the planner selected no tool (including planner failures).
 */
export interface ConfusionMatrix {
  /** Sorted expected tool names. */
  rows: string[];
  /** Sorted chosen tool names, with `(none)` last when it occurred. */
  columns: string[];
  /** `counts[row][column]` is the number of cases in that cell. */
  counts: Record<string, Record<string, number>>;
  /** Row-major counts aligned with {@link rows} and {@link columns}. */
  matrix: number[][];
}

/** The report returned by {@link runEvals}. */
export interface EvalReport {
  /** Number of cases that ran. */
  total: number;
  /** Number of cases that passed. */
  passed: number;
  /** `passed / total`, or `0` for an empty suite. */
  passRate: number;
  /** One result per case, in case order. */
  results: EvalResult[];
  /** Aggregate expected/chosen counts. */
  confusion: ConfusionMatrix;
  /** Human-readable ASCII table, including the confusion matrix. */
  summary(): string;
  /** Pretty-printed JSON containing the serializable report fields. */
  toJSON(): string;
}

/** The serializable payload produced by {@link EvalReport.toJSON}. */
export interface EvalReportJSON {
  total: number;
  passed: number;
  passRate: number;
  results: EvalResult[];
  confusion: ConfusionMatrix;
}

/** Options for {@link runEvals}. */
export interface RunEvalsOptions {
  /** Registry used to build the scoped tool catalog. */
  registry: ActionRegistry;
  /** Cases, executed sequentially in array order. */
  cases: EvalCase[];
  /** Planner under test. */
  planner: Planner;
  /** Scopes used to filter visible tools. Defaults to `["*"]`. */
  scopes?: string[];
  /** Optional system prompt shared by every case. */
  system?: string;
}

/** The result of comparing actual arguments with an expected subset. */
export interface ArgumentScore {
  /** True when every expected field is present and deep-equal. */
  passed: boolean;
  /** Expected paths that were missing or held a different value. */
  missingArgs: string[];
  /** Top-level actual keys not present in the expectation. */
  extraArgs: string[];
}

/** The result of {@link lintRegistry}. */
export interface LintReport {
  /** Core validation issues plus evals-specific description advice. */
  issues: RegistryIssue[];
  /** Sorted, unique pairs of tool names with similar descriptions. */
  ambiguous: Array<[string, string]>;
  /** 0-100 quality score: 100 - 20 per error - 5 per warning, floored at 0. */
  score: number;
}
