/** Narrow an unknown value to a plain object record. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Return a string only when it is present and non-empty after trimming. */
export function nonEmptyString(value: unknown): string | undefined {
  if (typeof value !== "string" || value.trim() === "") return undefined;
  return value;
}

/** De-duplicate strings while preserving their original order and casing. */
export function uniqueStrings(values: readonly unknown[]): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string" || value.length === 0 || seen.has(value)) continue;
    seen.add(value);
    result.push(value);
  }
  return result;
}

/** Merge scope arrays without duplicates. */
export function mergeScopes(
  ...groups: ReadonlyArray<readonly string[] | undefined>
): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const group of groups) {
    if (!group) continue;
    for (const scope of group) {
      if (typeof scope !== "string" || scope.length === 0 || seen.has(scope)) continue;
      seen.add(scope);
      result.push(scope);
    }
  }
  return result;
}

/** Remove control characters and escape a value for an HTTP quoted-string. */
export function quoteHeaderValue(value: string): string {
  const sanitized = value.replace(/[\u0000-\u001f\u007f]/g, "");
  return sanitized.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/** Read a bearer token from an Authorization header, case-insensitively. */
export function readBearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const match = /^\s*Bearer\s+(\S+)\s*$/i.exec(header);
  return match?.[1] ?? null;
}
