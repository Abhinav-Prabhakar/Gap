import { defineAction } from "gapmcp-core";
import type { AnyAction } from "gapmcp-core";

/** Build a minimal action for eval tests. */
export function tool(
  name: string,
  description: string,
  options: { scopes?: string[]; readOnly?: boolean; tags?: string[] } = {},
): AnyAction {
  const readOnly = options.readOnly ?? false;
  return defineAction({
    name,
    description,
    scopes: options.scopes ?? [],
    tags: readOnly ? ["read-only"] : options.tags,
    annotations: readOnly ? { readOnlyHint: true } : undefined,
    execute: () => ({ ok: true }),
  });
}
