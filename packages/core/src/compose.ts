import type { z, ZodType } from "zod";
import type { ActionContext, ActionDefinition, AnyAction } from "./types";
import { parseValue } from "./schema";

/**
 * Run another action from inside a skill. Input is validated with the child
 * action's schema; the same context (principal, scopes, signal, dry-run) flows
 * through, so policy cannot be bypassed by composition.
 */
export async function runAction<O = unknown>(
  action: AnyAction,
  input: unknown,
  ctx: ActionContext,
): Promise<O> {
  const parsed = action.input ? parseValue(action.input, input) : input;
  return action.execute(parsed, ctx) as Promise<O>;
}

export type SkillRunner = <O = unknown>(action: AnyAction, input: unknown) => Promise<O>;

export interface SkillSpec<I, O> extends Omit<ActionDefinition<I, O>, "execute" | "scopes"> {
  /** Actions this skill composes. Their scopes are required in addition to `scopes`. */
  uses: AnyAction[];
  scopes?: string[];
  execute: (input: I, ctx: ActionContext, run: SkillRunner) => O | Promise<O>;
}

/**
 * A compound action: one tool call that performs a short, deterministic workflow
 * of other actions. Prefer this over making the model orchestrate six calls.
 */
export function defineSkill<S extends ZodType, O>(
  spec: Omit<SkillSpec<z.infer<S>, O>, "input"> & { input: S },
): ActionDefinition<z.infer<S>, O>;
export function defineSkill<I = unknown, O = unknown>(spec: SkillSpec<I, O>): ActionDefinition<I, O>;
export function defineSkill<I = unknown, O = unknown>(spec: SkillSpec<I, O>): ActionDefinition<I, O> {
  const scopes = [...new Set([...spec.uses.flatMap((action) => action.scopes ?? []), ...(spec.scopes ?? [])])];
  const { uses: _uses, ...rest } = spec;
  return {
    ...rest,
    scopes,
    risk: spec.risk ?? "medium",
    execute: (input, ctx) => spec.execute(input, ctx, (action, args) => runAction(action, args, ctx)),
  };
}
