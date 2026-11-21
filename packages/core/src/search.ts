import type { ActionRegistry } from "./registry";
import type { AnyAction } from "./types";

export interface SearchResult {
  action: AnyAction;
  score: number;
  matched: string[];
}

function tokenize(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length > 1);
}

/**
 * Rank actions for a natural-language query. Useful for progressive disclosure:
 * expose a `tools.search` meta-tool instead of hundreds of tools at once.
 */
export function searchActions(
  registry: ActionRegistry,
  query: string,
  options: { limit?: number; scopes?: string[] } = {},
): SearchResult[] {
  const terms = tokenize(query);
  if (terms.length === 0) return [];
  const limit = options.limit ?? 10;
  const actions = options.scopes ? registry.visibleTo(options.scopes) : registry.list();

  const results: SearchResult[] = [];
  for (const action of actions) {
    const nameTokens = new Set(tokenize(action.name));
    const descriptionTokens = new Set(tokenize(action.description));
    const tagTokens = new Set((action.tags ?? []).flatMap(tokenize));
    let score = 0;
    const matched = new Set<string>();

    for (const term of terms) {
      if (nameTokens.has(term)) {
        score += 6;
        matched.add(term);
      }
      if (tagTokens.has(term)) {
        score += 4;
        matched.add(term);
      }
      if (descriptionTokens.has(term)) {
        score += 2;
        matched.add(term);
      }
      for (const token of [...nameTokens, ...descriptionTokens]) {
        if (token !== term && (token.startsWith(term) || term.startsWith(token))) {
          score += 1;
          matched.add(term);
        }
      }
    }
    if (score > 0) results.push({ action, score, matched: [...matched] });
  }

  return results.sort((a, b) => b.score - a.score || a.action.name.localeCompare(b.action.name)).slice(0, limit);
}
