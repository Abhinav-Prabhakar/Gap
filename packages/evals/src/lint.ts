import { GapError } from "gapmcp-core";
import type { ActionRegistry, AnyAction, RegistryIssue } from "gapmcp-core";
import type { LintReport } from "./types";

/** Tool descriptions above this estimate are considered context-heavy. */
const TOKEN_WARN_THRESHOLD = 120;

/** Default Jaccard similarity at which two tools are flagged as ambiguous. */
const AMBIGUITY_THRESHOLD = 0.55;

const STOPWORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "by",
  "for",
  "from",
  "has",
  "have",
  "if",
  "in",
  "into",
  "is",
  "it",
  "its",
  "of",
  "on",
  "or",
  "that",
  "the",
  "their",
  "this",
  "to",
  "was",
  "when",
  "which",
  "will",
  "with",
]);

/**
 * Verbs that describe an observable outcome. A non-read-only tool has to tell
 * the model what it changes; "do the thing" is not a usable description.
 */
const OUTCOME_PATTERN =
  /\b(return(?:s|ed|ing)?|creat(?:e|es|ed|ing)|updat(?:e|es|ed|ing)|delet(?:e|es|ed|ing)|remov(?:e|es|ed|ing)|send|sends|sent|charg(?:e|es|ed|ing)|refund(?:s|ed|ing)?|cancel(?:s|ed|ing)?|issu(?:e|es|ed|ing)|pay|pays|paid|transfer(?:s|red|ring)?|writ(?:e|es|ten|ing)|sav(?:e|es|ed|ing)|sets?|add(?:s|ed|ing)?|schedul(?:e|es|ed|ing)|publish(?:es|ed|ing)?|archiv(?:e|es|ed|ing)|approv(?:e|es|ed|ing)|reject(?:s|ed|ing)?|revok(?:e|es|ed|ing)|submit(?:s|ted|ting)?|enroll(?:s|ed|ing)?|assign(?:s|ed|ing)?|clos(?:e|es|ed|ing)|reopen(?:s|ed|ing)?|upload(?:s|ed|ing)?|import(?:s|ed|ing)?)\b/i;

function tokenize(text: string): Set<string> {
  const words = text.toLowerCase().split(/[^a-z0-9]+/);
  const tokens = new Set<string>();
  for (const word of words) {
    if (word.length > 1 && !STOPWORDS.has(word)) tokens.add(word);
  }
  return tokens;
}

function isReadOnly(action: AnyAction): boolean {
  return action.annotations?.readOnlyHint === true || action.tags?.includes("read-only") === true;
}

function jaccard(left: Set<string>, right: Set<string>): number {
  if (left.size === 0 || right.size === 0) return 0;
  let intersection = 0;
  for (const token of left) {
    if (right.has(token)) intersection += 1;
  }
  const union = left.size + right.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/**
 * Estimate description size in tokens using a deliberately simple word count
 * (`round(words * 1.3)`). This is a budget signal, not a tokenizer.
 */
export function estimateDescriptionTokens(description: string): number {
  const words = description.trim().split(/\s+/).filter(Boolean).length;
  return Math.round(words * 1.3);
}

/**
 * Find pairs of tools whose name + description tokens are at least
 * `threshold` similar by Jaccard index. Returned pairs are unique, each pair
 * is sorted, and the list is sorted lexicographically for deterministic
 * reports.
 */
export function findAmbiguousTools(
  registry: ActionRegistry,
  threshold: number = AMBIGUITY_THRESHOLD,
): Array<[string, string]> {
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1) {
    throw new GapError("Ambiguity threshold must be between 0 and 1.", {
      code: "INVALID_INPUT",
    });
  }

  const tools = registry.list().map((action) => ({
    name: action.name,
    tokens: tokenize(`${action.name} ${action.description}`),
  }));

  const pairs: Array<[string, string]> = [];
  for (let left = 0; left < tools.length; left += 1) {
    const first = tools[left];
    if (!first) continue;
    for (let right = left + 1; right < tools.length; right += 1) {
      const second = tools[right];
      if (!second) continue;
      if (jaccard(first.tokens, second.tokens) >= threshold) {
        pairs.push([first.name, second.name]);
      }
    }
  }

  pairs.sort(
    ([leftA, leftB], [rightA, rightB]) =>
      leftA.localeCompare(rightA) || leftB.localeCompare(rightB),
  );
  return pairs;
}

/**
 * Lint a registry for model-facing description quality.
 *
 * Core contract checks run first. Evals then adds a token budget warning
 * (>120 estimated tokens), an outcome warning for non-read-only tools whose
 * description names no side effect, and ambiguity warnings for near-duplicate
 * sibling tools. Every error costs 20 points and every warning costs 5, with
 * the score floored at 0.
 */
export function lintRegistry(registry: ActionRegistry): LintReport {
  const issues: RegistryIssue[] = [...registry.validate()];

  for (const action of registry.list()) {
    const description = action.description?.trim() ?? "";
    if (description.length === 0) continue;

    const tokens = estimateDescriptionTokens(description);
    if (tokens > TOKEN_WARN_THRESHOLD) {
      issues.push({
        level: "warn",
        code: "description.tokens",
        action: action.name,
        message: `Description is about ${tokens} tokens; aim for ${TOKEN_WARN_THRESHOLD} or fewer.`,
      });
    }

    if (!isReadOnly(action) && !OUTCOME_PATTERN.test(description)) {
      issues.push({
        level: "warn",
        code: "description.no_outcome",
        action: action.name,
        message:
          "Description does not state the action's outcome or side effect; name what it creates, changes, sends or deletes.",
      });
    }
  }

  const ambiguous = findAmbiguousTools(registry);
  for (const [left, right] of ambiguous) {
    issues.push({
      level: "warn",
      code: "description.ambiguous",
      action: left,
      message: `"${left}" and "${right}" have very similar names and descriptions; models may confuse them.`,
    });
  }

  const errors = issues.filter((issue) => issue.level === "error").length;
  const warnings = issues.filter((issue) => issue.level === "warn").length;
  const score = Math.max(0, 100 - errors * 20 - warnings * 5);

  return { issues, ambiguous, score };
}
