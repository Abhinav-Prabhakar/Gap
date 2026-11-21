import type { AnyAction, JsonSchema } from "./types";
import { toInputJsonSchema, toOutputJsonSchema } from "./schema";

export interface ActionChange {
  action: string;
  kind: "input" | "output" | "description" | "scopes" | "risk" | "deprecated" | "metadata";
  breaking: boolean;
  detail: string;
}

export interface RegistryDiff {
  added: string[];
  removed: string[];
  changed: ActionChange[];
  breaking: ActionChange[];
  compatible: boolean;
}

function typeOf(schema: JsonSchema | undefined): string {
  if (!schema) return "none";
  const type = schema.type;
  return Array.isArray(type) ? type.slice().sort().join("|") : String(type ?? "any");
}

function requiredFields(schema: JsonSchema | undefined): string[] {
  const required = schema?.required;
  return Array.isArray(required) ? required.map(String).sort() : [];
}

function properties(schema: JsonSchema | undefined): Record<string, JsonSchema> {
  const value = schema?.properties;
  return value && typeof value === "object" ? (value as Record<string, JsonSchema>) : {};
}

function enumValues(schema: JsonSchema | undefined): string[] | undefined {
  return Array.isArray(schema?.enum) ? schema.enum.map(String).sort() : undefined;
}

function diffInput(action: string, previous: JsonSchema, next: JsonSchema): ActionChange[] {
  const changes: ActionChange[] = [];
  const beforeProps = properties(previous);
  const afterProps = properties(next);
  const beforeRequired = requiredFields(previous);
  const afterRequired = requiredFields(next);

  for (const key of Object.keys(beforeProps)) {
    if (!(key in afterProps)) {
      changes.push({
        action,
        kind: "input",
        breaking: true,
        detail: `Input field "${key}" was removed.`,
      });
    }
  }
  for (const key of Object.keys(afterProps)) {
    if (!(key in beforeProps)) {
      const isRequired = afterRequired.includes(key);
      changes.push({
        action,
        kind: "input",
        breaking: isRequired,
        detail: `Input field "${key}" was added${isRequired ? " and is required" : ""}.`,
      });
      continue;
    }
    const before = beforeProps[key]!;
    const after = afterProps[key]!;
    if (typeOf(before) !== typeOf(after)) {
      changes.push({
        action,
        kind: "input",
        breaking: true,
        detail: `Input field "${key}" changed type from ${typeOf(before)} to ${typeOf(after)}.`,
      });
    }
    const beforeEnum = enumValues(before);
    const afterEnum = enumValues(after);
    if (beforeEnum && afterEnum && afterEnum.some((value) => !beforeEnum.includes(value))) {
      changes.push({
        action,
        kind: "input",
        breaking: true,
        detail: `Input field "${key}" narrowed its enum.`,
      });
    }
  }
  for (const key of afterRequired) {
    if (!beforeRequired.includes(key)) {
      const alreadyFlagged = changes.some(
        (change) => change.kind === "input" && change.detail.includes(`"${key}" was added`),
      );
      if (!alreadyFlagged) {
        changes.push({
          action,
          kind: "input",
          breaking: true,
          detail: `Input field "${key}" became required.`,
        });
      }
    }
  }
  return changes;
}

function diffOutput(action: string, previous: JsonSchema, next: JsonSchema): ActionChange[] {
  const changes: ActionChange[] = [];
  if (typeOf(previous) !== typeOf(next)) {
    changes.push({
      action,
      kind: "output",
      breaking: true,
      detail: `Output type changed from ${typeOf(previous)} to ${typeOf(next)}.`,
    });
  }
  return changes;
}

/**
 * Semantic diff between two registry snapshots. Use it as a contract test:
 * removed actions and narrower inputs break existing clients and should fail a
 * release.
 */
export function diffRegistries(
  previous: Iterable<AnyAction>,
  next: Iterable<AnyAction>,
): RegistryDiff {
  const before = new Map([...previous].map((action) => [action.name, action]));
  const after = new Map([...next].map((action) => [action.name, action]));
  const added: string[] = [];
  const removed: string[] = [];
  const changed: ActionChange[] = [];
  for (const name of before.keys()) {
    if (!after.has(name)) {
      removed.push(name);
      changed.push({
        action: name,
        kind: "metadata",
        breaking: true,
        detail: "Action was removed.",
      });
    }
  }
  for (const name of after.keys()) {
    if (!before.has(name)) added.push(name);
  }

  for (const [name, oldAction] of before) {
    const newAction = after.get(name);
    if (!newAction) continue;

    const oldInput = toInputJsonSchema(oldAction.input);
    const newInput = toInputJsonSchema(newAction.input);
    changed.push(...diffInput(name, oldInput, newInput));

    const oldOutput = toOutputJsonSchema(oldAction.output);
    const newOutput = toOutputJsonSchema(newAction.output);
    if (oldOutput && newOutput) changed.push(...diffOutput(name, oldOutput, newOutput));

    const oldScopes = [...(oldAction.scopes ?? [])].sort();
    const newScopes = [...(newAction.scopes ?? [])].sort();
    if (oldScopes.join(",") !== newScopes.join(",")) {
      const addedScopes = newScopes.filter((scope) => !oldScopes.includes(scope));
      changed.push({
        action: name,
        kind: "scopes",
        breaking: addedScopes.length > 0,
        detail: addedScopes.length
          ? `Required scopes added: ${addedScopes.join(", ")}.`
          : `Required scopes relaxed: ${oldScopes.filter((scope) => !newScopes.includes(scope)).join(", ")}.`,
      });
    }

    if ((oldAction.risk ?? "low") !== (newAction.risk ?? "low")) {
      changed.push({
        action: name,
        kind: "risk",
        breaking: false,
        detail: `Risk changed from ${oldAction.risk ?? "low"} to ${newAction.risk ?? "low"}.`,
      });
    }
    if (Boolean(oldAction.deprecated) !== Boolean(newAction.deprecated)) {
      changed.push({
        action: name,
        kind: "deprecated",
        breaking: false,
        detail: newAction.deprecated ? "Action is now deprecated." : "Action is no longer deprecated.",
      });
    }
    if (oldAction.description !== newAction.description) {
      changed.push({
        action: name,
        kind: "description",
        breaking: false,
        detail: "Description changed; re-run tool-selection evals.",
      });
    }
  }

  const breaking = changed.filter((change) => change.breaking);
  return {
    added: added.sort(),
    removed: removed.sort(),
    changed,
    breaking,
    compatible: breaking.length === 0,
  };
}
