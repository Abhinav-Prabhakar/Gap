import type {
  AnyAction,
  ActionFilter,
  RegistryIssue,
  ToolDescriptor,
  ToolDescriptorOptions,
} from "./types";
import { GapError } from "./errors";
import { hasScopes } from "./utils";
import {
  isObjectSchema,
  schemaPathsWithoutDescriptions,
  toInputJsonSchema,
  toOutputJsonSchema,
} from "./schema";

const NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$/;
const SCOPE_PATTERN = /^[a-z0-9][a-z0-9:_-]*$/;
const DESTRUCTIVE_VERBS = /(^|[.:_-])(delete|remove|destroy|refund|charge|transfer|send|cancel|revoke|drop|purge)([.:_-]|$)/i;

function matchesFilter(action: AnyAction, filter?: ActionFilter): boolean {
  if (!filter) return true;
  if (filter.names && !filter.names.includes(action.name)) return false;
  if (filter.namespace && !action.name.startsWith(`${filter.namespace}.`)) return false;
  if (filter.tags && filter.tags.length > 0) {
    const tags = action.tags ?? [];
    if (!filter.tags.every((tag) => tags.includes(tag))) return false;
  }
  if (filter.scopes && filter.scopes.length > 0 && !hasScopes(action.scopes, filter.scopes)) {
    return false;
  }
  if (filter.include && !filter.include(action)) return false;
  return true;
}

/**
 * An immutable-by-convention set of actions. Visibility is scope-aware, which
 * is what stops an agent from even seeing tools it could never call.
 */
export class ActionRegistry {
  readonly #actions = new Map<string, AnyAction>();

  constructor(actions: Iterable<AnyAction> = []) {
    this.add(...actions);
  }

  get size(): number {
    return this.#actions.size;
  }

  add(...actions: AnyAction[]): this {
    for (const action of actions) {
      if (!action || typeof action !== "object") {
        throw new GapError("Cannot register a non-action value.", { code: "INTERNAL", expose: false });
      }
      if (typeof action.name !== "string" || !NAME_PATTERN.test(action.name)) {
        throw new GapError(
          `Invalid action name "${String(action.name)}". Use a dot-namespaced name such as "invoices.create".`,
          { code: "INTERNAL", expose: false },
        );
      }
      if (this.#actions.has(action.name)) {
        throw new GapError(`Action "${action.name}" is already registered.`, {
          code: "CONFLICT",
          expose: false,
        });
      }
      if (typeof action.execute !== "function") {
        throw new GapError(`Action "${action.name}" has no execute function.`, {
          code: "INTERNAL",
          expose: false,
        });
      }
      this.#actions.set(action.name, action);
    }
    return this;
  }

  remove(name: string): boolean {
    return this.#actions.delete(name);
  }

  /** Remove every action. Used by gateways that refresh an upstream catalog. */
  clear(): this {
    this.#actions.clear();
    return this;
  }

  get(name: string): AnyAction | undefined {
    return this.#actions.get(name);
  }

  require(name: string): AnyAction {
    const action = this.#actions.get(name);
    if (!action) {
      throw new GapError(`Unknown action "${name}".`, { code: "NOT_FOUND" });
    }
    return action;
  }

  has(name: string): boolean {
    return this.#actions.has(name);
  }

  list(filter?: ActionFilter): AnyAction[] {
    return [...this.#actions.values()]
      .filter((action) => matchesFilter(action, filter))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Tools a principal with these scopes is allowed to discover. */
  visibleTo(scopes: readonly string[] | undefined, filter?: ActionFilter): AnyAction[] {
    return this.list(filter).filter((action) => hasScopes(scopes, action.scopes));
  }

  namespaces(): string[] {
    return [...new Set([...this.#actions.keys()].map((name) => name.split(".")[0]!))].sort();
  }

  toToolDescriptors(options: ToolDescriptorOptions = {}): ToolDescriptor[] {
    const actions = options.scopes
      ? this.visibleTo(options.scopes, options.filter)
      : this.list(options.filter);

    return actions.map((action) => toToolDescriptor(action));
  }

  /** CI-friendly contract checks. Errors should fail a build; warns are advice. */
  validate(): RegistryIssue[] {
    const issues: RegistryIssue[] = [];
    for (const action of this.list()) {
      if (!NAME_PATTERN.test(action.name)) {
        issues.push({ level: "error", code: "name", action: action.name, message: "Invalid tool name." });
      }
      if (!action.description || action.description.trim().length === 0) {
        issues.push({
          level: "error",
          code: "description.missing",
          action: action.name,
          message: "Every action needs a description written for the model.",
        });
      } else if (action.description.length < 30) {
        issues.push({
          level: "warn",
          code: "description.short",
          action: action.name,
          message: "Description is shorter than 30 characters; models select tools by description.",
        });
      } else if (action.description.length > 2000) {
        issues.push({
          level: "warn",
          code: "description.long",
          action: action.name,
          message: "Description exceeds 2000 characters and spends context budget.",
        });
      }

      if (action.input) {
        const schema = toInputJsonSchema(action.input);
        if (!isObjectSchema(schema)) {
          issues.push({
            level: "error",
            code: "input.not_object",
            action: action.name,
            message: "MCP tool input must be an object schema.",
          });
        }
        const missing = schemaPathsWithoutDescriptions(schema);
        if (missing.length > 0) {
          issues.push({
            level: "warn",
            code: "input.undescribed",
            action: action.name,
            message: `Undescribed input field(s): ${missing.slice(0, 8).join(", ")}.`,
          });
        }
      }

      for (const scope of action.scopes ?? []) {
        if (!SCOPE_PATTERN.test(scope)) {
          issues.push({
            level: "warn",
            code: "scope.format",
            action: action.name,
            message: `Scope "${scope}" does not follow the resource:verb convention.`,
          });
        }
      }

      const risky = action.risk === "high" || action.risk === "critical";
      if (risky && action.confirm !== true && typeof action.confirm !== "function") {
        issues.push({
          level: "warn",
          code: "risk.no_confirmation",
          action: action.name,
          message: `${action.risk} risk action does not require confirmation.`,
        });
      }
      if (DESTRUCTIVE_VERBS.test(action.name) && action.confirm !== true && typeof action.confirm !== "function") {
        issues.push({
          level: "warn",
          code: "destructive.no_confirmation",
          action: action.name,
          message: "Name looks destructive but the action does not require confirmation.",
        });
      }
      if (risky && action.idempotent !== true) {
        issues.push({
          level: "warn",
          code: "risk.not_idempotent",
          action: action.name,
          message: "High-risk action is not idempotent; retries can duplicate effects.",
        });
      }
      if (action.deprecated) {
        issues.push({
          level: "warn",
          code: "deprecated",
          action: action.name,
          message: typeof action.deprecated === "string" ? action.deprecated : "Action is deprecated.",
        });
      }
      if (action.ui && !action.ui.route && !action.ui.action) {
        issues.push({
          level: "warn",
          code: "ui.incomplete",
          action: action.name,
          message: "UI binding has neither a route nor an action id.",
        });
      }
    }
    return issues;
  }
}

export function toToolDescriptor(action: AnyAction): ToolDescriptor {
  const annotations = {
    title: action.title ?? action.annotations?.title ?? action.name,
    readOnlyHint: action.annotations?.readOnlyHint ?? action.tags?.includes("read-only") ?? false,
    destructiveHint:
      action.annotations?.destructiveHint ??
      (action.risk === "critical" || action.risk === "high") ??
      false,
    idempotentHint: action.annotations?.idempotentHint ?? action.idempotent ?? false,
    openWorldHint: action.annotations?.openWorldHint ?? false,
  };

  const outputSchema = toOutputJsonSchema(action.output);
  const meta: Record<string, unknown> = {
    "gap/risk": action.risk ?? "low",
    "gap/scopes": action.scopes ?? [],
    "gap/version": action.version ?? 1,
    "gap/idempotent": Boolean(action.idempotent),
    ...(action.tags?.length ? { "gap/tags": action.tags } : {}),
    ...(action.ui ? { "gap/ui": action.ui } : {}),
    ...(action.task ? { "gap/task": true } : {}),
    ...(action.deprecated ? { "gap/deprecated": action.deprecated } : {}),
    ...(action.meta ?? {}),
  };

  return {
    name: action.name,
    title: annotations.title,
    description: action.description,
    inputSchema: toInputJsonSchema(action.input),
    ...(outputSchema ? { outputSchema } : {}),
    annotations,
    _meta: meta,
  };
}

export function createRegistry(...actions: AnyAction[]): ActionRegistry {
  return new ActionRegistry(actions);
}
