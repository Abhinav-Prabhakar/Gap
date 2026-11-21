import type { ArgumentScore } from "./types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Structural equality for JSON-like values. Arrays must match element for
 * element and object key order is ignored; prototypes are not considered.
 */
function deepEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) {
      return false;
    }
    return left.every((item, index) => deepEqual(item, right[index]));
  }
  if (!isRecord(left) || !isRecord(right)) return false;

  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  if (leftKeys.length !== rightKeys.length) return false;
  return leftKeys.every(
    (key) => Object.prototype.hasOwnProperty.call(right, key) && deepEqual(left[key], right[key]),
  );
}

/**
 * Collect expected paths that are absent or unequal. A missing parent is
 * reported once (`filter`), while a missing child of a present parent is
 * reported with a dot path (`filter.status`).
 */
function collectMissing(
  expected: Record<string, unknown>,
  actual: Record<string, unknown>,
  prefix: string,
  out: string[],
): void {
  for (const [key, expectedValue] of Object.entries(expected)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (!Object.prototype.hasOwnProperty.call(actual, key)) {
      out.push(path);
      continue;
    }
    const actualValue = actual[key];
    if (isRecord(expectedValue)) {
      if (!isRecord(actualValue)) {
        out.push(path);
        continue;
      }
      collectMissing(expectedValue, actualValue, path, out);
      continue;
    }
    if (!deepEqual(expectedValue, actualValue)) out.push(path);
  }
}

/**
 * Score actual tool arguments against an expected subset.
 *
 * Objects are matched recursively and may contain extra keys. Arrays and
 * primitives must match exactly. Extra top-level keys are reported but do not
 * fail the match, which keeps eval cases focused on intent rather than
 * incidental model verbosity. When `expected` is `undefined`, every argument
 * shape passes.
 */
export function scoreArgs(
  expected: Record<string, unknown> | undefined,
  actual: unknown,
): ArgumentScore {
  if (expected === undefined) {
    return { passed: true, missingArgs: [], extraArgs: [] };
  }

  if (!isRecord(actual)) {
    return {
      passed: false,
      missingArgs: Object.keys(expected).sort(),
      extraArgs: [],
    };
  }

  const missingArgs: string[] = [];
  collectMissing(expected, actual, "", missingArgs);
  missingArgs.sort();

  const extraArgs = Object.keys(actual)
    .filter((key) => !Object.prototype.hasOwnProperty.call(expected, key))
    .sort();

  return { passed: missingArgs.length === 0, missingArgs, extraArgs };
}
