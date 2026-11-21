/**
 * A single rule in a policy document. Rules are evaluated in document order
 * for deny precedence, but any matching deny beats a matching confirm and any
 * matching confirm beats the document default.
 */
export interface PolicyRule {
  /**
   * Tool names or namespace globs (`"invoices.*"`, `"*"`) this rule applies
   * to. When omitted the rule applies to every tool. An empty array matches
   * no tools.
   */
  tools?: string[];
  /**
   * Scopes the caller must all hold for this rule to apply. Wildcards follow
   * the core scope matcher (`"billing:*"` covers `"billing:write"`).
   */
  scopes?: string[];
  /** Hard-deny every matching invocation. */
  deny?: boolean;
  /** Require human confirmation for every matching invocation. */
  confirm?: boolean;
  /** Mark matching invocations as dry runs (`ctx.dryRun = true`). */
  dryRun?: boolean;
  /**
   * Deny when a numeric amount in the arguments exceeds this value. Amounts
   * are inspected recursively; see {@link PolicyRule.amountPaths}.
   */
  maxAmount?: number;
  /**
   * Dot/bracket paths to numeric amounts (for example `"order.total"` or
   * `"items[].price"`). Defaults to recursively finding `amount`, `total`,
   * `value`, `price` and `cost` keys. An empty array disables amount checks.
   */
  amountPaths?: string[];
  /**
   * Deny when an array in the arguments has more items than this value.
   * See {@link PolicyRule.arrayPaths}.
   */
  maxArrayLength?: number;
  /**
   * Dot/bracket paths to arrays. When omitted every array in the arguments is
   * checked. An empty array disables array-length checks.
   */
  arrayPaths?: string[];
  /** Dot paths to redact from arguments and results when this rule matches. */
  redact?: string[];
  /** Human-readable explanation propagated on a deny or confirm decision. */
  reason?: string;
}

/** A complete, versioned policy document. */
export interface PolicyDocument {
  /** Policy schema version. Only `1` is supported. */
  version: 1;
  /**
   * Decision when no rule matches. Defaults to `"allow"`. With `"deny"`, a
   * matching rule that neither denies nor confirms acts as an explicit allow.
   */
  default?: "allow" | "deny";
  /** Ordered rules. The first matching deny wins. */
  rules: PolicyRule[];
  /** Dot paths always redacted when the invocation is not denied. */
  redact?: string[];
  /** Tool names or globs that always require human confirmation. */
  confirm?: string[];
  /** Tool names or globs that are always denied. */
  deny?: string[];
}
