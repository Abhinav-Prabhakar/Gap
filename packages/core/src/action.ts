import type { z, ZodType } from "zod";
import type {
  ActionContext,
  ActionDefinition,
  AnyAction,
  SchemaLike,
} from "./types";

type AnyZod = ZodType<any, any, any>;

export type ActionSpec<I, O> = Omit<ActionDefinition<I, O>, "input" | "output" | "execute"> & {
  input?: SchemaLike;
  output?: SchemaLike;
  execute: (input: I, ctx: ActionContext) => O | Promise<O>;
};

export type ZodActionSpec<S extends AnyZod, O> = Omit<
  ActionDefinition<z.infer<S>, O>,
  "input" | "output" | "execute"
> & {
  input: S;
  output?: ZodType<O>;
  execute: (input: z.infer<S>, ctx: ActionContext) => O | Promise<O>;
};

function normalizeName(name: string): string {
  return name.trim().replace(/\s+/g, ".");
}

/**
 * Define an action with a Zod input schema. The handler is typed from the
 * schema, and the same schema becomes the MCP JSON Schema.
 */
export function defineAction<S extends AnyZod, O>(spec: ZodActionSpec<S, O>): ActionDefinition<z.infer<S>, O>;
export function defineAction<I = unknown, O = unknown>(spec: ActionSpec<I, O>): ActionDefinition<I, O>;
export function defineAction<I = unknown, O = unknown>(
  spec: ActionSpec<I, O> | ZodActionSpec<AnyZod, O>,
): ActionDefinition<I, O> {
  const normalized = {
    ...spec,
    name: normalizeName(spec.name),
    risk: spec.risk ?? "low",
  } as ActionDefinition<I, O>;
  return normalized;
}

/** Alias for `defineAction`, matching the common `action({...})` style. */
export const action = defineAction;

export function defineActions(...specs: AnyAction[]): AnyAction[] {
  return specs;
}

export function isActionDefinition(value: unknown): value is AnyAction {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { name?: unknown }).name === "string" &&
    typeof (value as { execute?: unknown }).execute === "function"
  );
}

export function isActionArray(value: unknown): value is AnyAction[] {
  return Array.isArray(value) && value.every(isActionDefinition);
}
