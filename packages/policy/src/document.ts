import { invalidInput } from "gapmcp-core";
import type { ValidationIssue } from "gapmcp-core";
import type { PolicyDocument, PolicyRule } from "./types";

const INVALID_POLICY = "Invalid policy document.";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function issue(
  issues: ValidationIssue[],
  path: string,
  message: string,
  code: string,
): void {
  issues.push({ path, message, code });
}

function validateStringArray(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): void {
  if (value === undefined) return;
  if (!Array.isArray(value)) {
    issue(issues, path, "Expected an array of non-empty strings.", "invalid_type");
    return;
  }
  value.forEach((entry, index) => {
    if (typeof entry !== "string" || entry.trim().length === 0) {
      issue(issues, `${path}[${index}]`, "Expected a non-empty string.", "invalid_value");
    }
  });
}

function validateRule(raw: unknown, path: string, issues: ValidationIssue[]): void {
  if (!isRecord(raw)) {
    issue(issues, path, "Expected a policy rule object.", "invalid_type");
    return;
  }

  validateStringArray(raw.tools, `${path}.tools`, issues);
  validateStringArray(raw.scopes, `${path}.scopes`, issues);
  validateStringArray(raw.amountPaths, `${path}.amountPaths`, issues);
  validateStringArray(raw.arrayPaths, `${path}.arrayPaths`, issues);
  validateStringArray(raw.redact, `${path}.redact`, issues);

  for (const key of ["deny", "confirm", "dryRun"] as const) {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean") {
      issue(issues, `${path}.${key}`, "Expected a boolean.", "invalid_type");
    }
  }

  if (
    raw.maxAmount !== undefined &&
    (typeof raw.maxAmount !== "number" ||
      !Number.isFinite(raw.maxAmount) ||
      raw.maxAmount < 0)
  ) {
    issue(
      issues,
      `${path}.maxAmount`,
      "Expected a finite, non-negative number.",
      "invalid_value",
    );
  }

  if (
    raw.maxArrayLength !== undefined &&
    (typeof raw.maxArrayLength !== "number" ||
      !Number.isInteger(raw.maxArrayLength) ||
      raw.maxArrayLength < 0)
  ) {
    issue(
      issues,
      `${path}.maxArrayLength`,
      "Expected a non-negative integer.",
      "invalid_value",
    );
  }

  if (raw.reason !== undefined && typeof raw.reason !== "string") {
    issue(issues, `${path}.reason`, "Expected a string.", "invalid_type");
  }
}

function normalizeRule(raw: Record<string, unknown>): PolicyRule {
  const rule: PolicyRule = {};
  if (raw.tools !== undefined) rule.tools = [...(raw.tools as string[])];
  if (raw.scopes !== undefined) rule.scopes = [...(raw.scopes as string[])];
  if (raw.deny !== undefined) rule.deny = raw.deny as boolean;
  if (raw.confirm !== undefined) rule.confirm = raw.confirm as boolean;
  if (raw.dryRun !== undefined) rule.dryRun = raw.dryRun as boolean;
  if (raw.maxAmount !== undefined) rule.maxAmount = raw.maxAmount as number;
  if (raw.amountPaths !== undefined) {
    rule.amountPaths = [...(raw.amountPaths as string[])];
  }
  if (raw.maxArrayLength !== undefined) {
    rule.maxArrayLength = raw.maxArrayLength as number;
  }
  if (raw.arrayPaths !== undefined) {
    rule.arrayPaths = [...(raw.arrayPaths as string[])];
  }
  if (raw.redact !== undefined) rule.redact = [...(raw.redact as string[])];
  if (raw.reason !== undefined) rule.reason = raw.reason as string;
  return rule;
}

/**
 * Validate an untrusted value and return a normalized policy document. Every
 * issue is collected so a bad document fails with one actionable error rather
 * than revealing one field at a time.
 */
function normalizePolicy(value: unknown): PolicyDocument {
  if (!isRecord(value)) {
    throw invalidInput(INVALID_POLICY, {
      issues: [
        {
          path: "(root)",
          message: "Policy must be an object.",
          code: "invalid_type",
        },
      ],
    });
  }

  const issues: ValidationIssue[] = [];

  if (value.version === undefined) {
    issue(issues, "version", "Policy version is required; expected 1.", "required");
  } else if (value.version !== 1) {
    issue(
      issues,
      "version",
      `Unsupported policy version ${String(value.version)}; expected 1.`,
      "invalid_value",
    );
  }

  if (
    value.default !== undefined &&
    value.default !== "allow" &&
    value.default !== "deny"
  ) {
    issue(issues, "default", 'Expected "allow" or "deny".', "invalid_value");
  }

  validateStringArray(value.redact, "redact", issues);
  validateStringArray(value.confirm, "confirm", issues);
  validateStringArray(value.deny, "deny", issues);

  if (!Array.isArray(value.rules)) {
    issue(
      issues,
      "rules",
      value.rules === undefined
        ? "Policy rules are required."
        : "Expected an array of rules.",
      value.rules === undefined ? "required" : "invalid_type",
    );
  } else {
    value.rules.forEach((rule, index) => {
      validateRule(rule, `rules[${index}]`, issues);
    });
  }

  if (issues.length > 0) {
    throw invalidInput(INVALID_POLICY, { issues });
  }

  const rawRules = (value.rules as unknown[]).filter(isRecord);
  const document: PolicyDocument = {
    version: 1,
    rules: rawRules.map(normalizeRule),
  };
  if (value.default !== undefined) {
    document.default = value.default as "allow" | "deny";
  }
  if (value.redact !== undefined) {
    document.redact = [...(value.redact as string[])];
  }
  if (value.confirm !== undefined) {
    document.confirm = [...(value.confirm as string[])];
  }
  if (value.deny !== undefined) {
    document.deny = [...(value.deny as string[])];
  }
  return document;
}

/**
 * Type helper for authoring a policy in TypeScript. The document is validated
 * immediately, so a typo or wrong version fails at definition time instead of
 * on the first tool call. The original object is returned unchanged.
 */
export function definePolicy(document: PolicyDocument): PolicyDocument {
  normalizePolicy(document);
  return document;
}

/**
 * Parse and validate a policy document from JSON text or a plain object.
 *
 * @throws GapError `INVALID_INPUT` when the JSON is malformed, the version is
 * not `1`, or any rule/document field has the wrong shape. Details contain an
 * `issues` array with one entry per problem.
 */
export function parsePolicy(input: string | PolicyDocument): PolicyDocument {
  if (typeof input !== "string") {
    return normalizePolicy(input);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    throw invalidInput("Policy must be valid JSON.", {
      issues: [
        {
          path: "(root)",
          message: "Invalid JSON.",
          code: "invalid_json",
        },
      ],
    });
  }
  return normalizePolicy(parsed);
}
