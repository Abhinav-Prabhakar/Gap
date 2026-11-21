import { hasScopes } from "gapmcp-core";
import type {
  PolicyDecision,
  PolicyEngine,
  PolicyEvaluationInput,
} from "gapmcp-core";
import { parsePolicy } from "./document";
import type { PolicyDocument, PolicyRule } from "./types";

const DEFAULT_AMOUNT_PATHS: readonly string[] = [
  "amount",
  "total",
  "value",
  "price",
  "cost",
];

interface LimitViolation {
  path: string;
  value: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Match a tool name against an exact name, a `*` wildcard, or a namespace glob
 * such as `"invoices.*"`. Namespace globs do not match the namespace itself.
 */
function matchesTool(pattern: string, name: string): boolean {
  if (pattern === "*" || pattern === name) return true;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    return name.startsWith(`${prefix}.`);
  }
  return false;
}

function matchesAny(patterns: readonly string[] | undefined, name: string): boolean {
  return patterns?.some((pattern) => matchesTool(pattern, name)) ?? false;
}

function ruleMatches(
  rule: PolicyRule,
  actionName: string,
  scopes: readonly string[],
): boolean {
  if (!hasScopes(scopes, rule.scopes)) return false;
  if (rule.tools === undefined) return true;
  return rule.tools.some((pattern) => matchesTool(pattern, actionName));
}

function mergePaths(
  ...groups: Array<readonly string[] | undefined>
): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const group of groups) {
    for (const path of group ?? []) {
      if (seen.has(path)) continue;
      seen.add(path);
      result.push(path);
    }
  }
  return result;
}

function isSimplePath(path: string): boolean {
  return !path.includes(".") && !path.includes("[");
}

function pathSegments(path: string): string[] {
  return path
    .replace(/\[(\*|\d*)\]/g, (_match, inner: string) => `.${inner || "*"}`)
    .split(".")
    .map((part) => part.trim())
    .filter(Boolean);
}

/**
 * Resolve every value selected by a dot/bracket path. `*`, `[]` and `[*]`
 * expand arrays (and object values) so `"items[].price"` yields all prices.
 */
function resolvePathValues(value: unknown, path: string): unknown[] {
  let current: unknown[] = [value];
  for (const segment of pathSegments(path)) {
    const next: unknown[] = [];
    for (const node of current) {
      if (node === null || node === undefined) continue;
      if (Array.isArray(node)) {
        if (segment === "*") {
          next.push(...node);
          continue;
        }
        const index = Number(segment);
        if (Number.isInteger(index) && index >= 0 && index < node.length) {
          next.push(node[index]);
        }
        continue;
      }
      if (isRecord(node)) {
        if (segment === "*") {
          next.push(...Object.values(node));
        } else {
          next.push(node[segment]);
        }
      }
    }
    current = next.filter((entry) => entry !== undefined);
  }
  return current;
}

/**
 * Find the first numeric amount at a configured path that exceeds the limit.
 * Simple key names are searched recursively at any depth, which covers the
 * default amount keys. Explicit dot/bracket paths are resolved from the root.
 */
function findAmountViolation(
  value: unknown,
  paths: readonly string[],
  maxAmount: number,
): LimitViolation | undefined {
  const simple = new Set<string>();
  const complex: string[] = [];
  for (const path of paths) {
    if (isSimplePath(path)) simple.add(path);
    else complex.push(path);
  }

  if (simple.size > 0) {
    const seen = new WeakSet<object>();
    const visit = (node: unknown, path: string): LimitViolation | undefined => {
      if (Array.isArray(node)) {
        if (seen.has(node)) return undefined;
        seen.add(node);
        for (let index = 0; index < node.length; index += 1) {
          const violation = visit(node[index], `${path}[${index}]`);
          if (violation) return violation;
        }
        return undefined;
      }
      if (!isRecord(node)) return undefined;
      if (seen.has(node)) return undefined;
      seen.add(node);

      for (const [key, child] of Object.entries(node)) {
        const childPath = path ? `${path}.${key}` : key;
        if (
          simple.has(key) &&
          typeof child === "number" &&
          Number.isFinite(child) &&
          child > maxAmount
        ) {
          return { path: childPath, value: child };
        }
        const violation = visit(child, childPath);
        if (violation) return violation;
      }
      return undefined;
    };

    const found = visit(value, "");
    if (found) return found;
  }

  for (const path of complex) {
    for (const candidate of resolvePathValues(value, path)) {
      if (
        typeof candidate === "number" &&
        Number.isFinite(candidate) &&
        candidate > maxAmount
      ) {
        return { path, value: candidate };
      }
    }
  }
  return undefined;
}

/**
 * Find the first array longer than the limit. With no configured paths, every
 * array reachable from the arguments is checked.
 */
function findArrayViolation(
  value: unknown,
  paths: readonly string[] | undefined,
  maxLength: number,
): LimitViolation | undefined {
  if (paths !== undefined) {
    for (const path of paths) {
      for (const candidate of resolvePathValues(value, path)) {
        if (Array.isArray(candidate) && candidate.length > maxLength) {
          return { path, value: candidate.length };
        }
      }
    }
    return undefined;
  }

  const seen = new WeakSet<object>();
  const visit = (node: unknown, path: string): LimitViolation | undefined => {
    if (Array.isArray(node)) {
      if (seen.has(node)) return undefined;
      seen.add(node);
      if (node.length > maxLength) {
        return { path: path || "(root)", value: node.length };
      }
      for (let index = 0; index < node.length; index += 1) {
        const violation = visit(node[index], `${path}[${index}]`);
        if (violation) return violation;
      }
      return undefined;
    }
    if (!isRecord(node)) return undefined;
    if (seen.has(node)) return undefined;
    seen.add(node);
    for (const [key, child] of Object.entries(node)) {
      const violation = visit(child, path ? `${path}.${key}` : key);
      if (violation) return violation;
    }
    return undefined;
  };

  return visit(value, "");
}

function amountReason(
  violation: LimitViolation,
  maxAmount: number,
): string {
  return `Amount ${violation.value} at "${violation.path}" exceeds the max amount of ${maxAmount}.`;
}

function arrayReason(
  violation: LimitViolation,
  maxLength: number,
): string {
  return `Array at "${violation.path}" has ${violation.value} items, exceeding the max length of ${maxLength}.`;
}

function limitDecision(
  reason: string,
  limit: number,
  violation: LimitViolation,
): PolicyDecision {
  return {
    decision: "deny",
    code: "LIMIT_EXCEEDED",
    reason,
    metadata: {
      limit,
      path: violation.path,
      value: violation.value,
    },
  };
}

/**
 * A policy engine backed by a declarative {@link PolicyDocument}.
 *
 * Evaluation order is deterministic:
 * 1. document-level `deny` globs
 * 2. the first matching rule deny (including limit violations)
 * 3. confirmations from the document or any matching rule
 * 4. the document default, where a `"deny"` default needs an explicit
 *    non-denying, non-confirming matching rule to allow the call
 *
 * Normal denials are returned as decisions, never thrown. Only an invalid
 * policy document throws (`GapError` with code `INVALID_INPUT`).
 */
export class GapPolicy implements PolicyEngine {
  /** The validated, normalized document this engine evaluates. */
  readonly document: PolicyDocument;

  constructor(input: PolicyDocument | string) {
    this.document = parsePolicy(input);
  }

  evaluate(input: PolicyEvaluationInput): PolicyDecision {
    const { action, args, ctx } = input;
    const actionName = action.name;
    const scopes = ctx.scopes ?? ctx.principal.scopes ?? [];
    const matching = this.document.rules.filter((rule) =>
      ruleMatches(rule, actionName, scopes),
    );

    if (matchesAny(this.document.deny, actionName)) {
      return {
        decision: "deny",
        code: "POLICY_DENIED",
        reason: "Denied by the policy document.",
      };
    }

    let confirmReason: string | undefined;
    let confirmMatched = false;

    for (const rule of matching) {
      if (rule.deny === true) {
        return {
          decision: "deny",
          code: "POLICY_DENIED",
          reason: rule.reason ?? "Denied by policy.",
        };
      }

      if (rule.maxAmount !== undefined) {
        const violation = findAmountViolation(
          args,
          rule.amountPaths ?? DEFAULT_AMOUNT_PATHS,
          rule.maxAmount,
        );
        if (violation) {
          return limitDecision(
            rule.reason ?? amountReason(violation, rule.maxAmount),
            rule.maxAmount,
            violation,
          );
        }
      }

      if (rule.maxArrayLength !== undefined) {
        const violation = findArrayViolation(
          args,
          rule.arrayPaths,
          rule.maxArrayLength,
        );
        if (violation) {
          return limitDecision(
            rule.reason ?? arrayReason(violation, rule.maxArrayLength),
            rule.maxArrayLength,
            violation,
          );
        }
      }

      if (rule.confirm === true && !confirmMatched) {
        confirmMatched = true;
        confirmReason = rule.reason ?? "Confirmation required by policy.";
      }
    }

    const documentConfirm = matchesAny(this.document.confirm, actionName);
    const redactPaths = mergePaths(
      this.document.redact,
      ...matching.map((rule) => rule.redact),
    );
    const dryRun = matching.some((rule) => rule.dryRun === true);
    const allowRule = matching.find(
      (rule) => rule.deny !== true && rule.confirm !== true,
    );

    const withRedactions = redactPaths.length > 0 ? { redactPaths } : {};
    const withDryRun = dryRun ? { metadata: { dryRun: true } } : {};

    if (confirmMatched || documentConfirm) {
      if (dryRun) ctx.dryRun = true;
      return {
        decision: "confirm",
        reason:
          confirmReason ?? "Confirmation required by the policy document.",
        ...withRedactions,
        ...withDryRun,
      };
    }

    if (this.document.default === "deny" && !allowRule) {
      return {
        decision: "deny",
        code: "POLICY_DENIED",
        reason: "Denied by default policy.",
      };
    }

    if (dryRun) ctx.dryRun = true;

    return {
      decision: "allow",
      ...(allowRule?.reason === undefined ? {} : { reason: allowRule.reason }),
      ...withRedactions,
      ...withDryRun,
    };
  }
}
