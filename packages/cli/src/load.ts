import path from "node:path";
import { pathToFileURL } from "node:url";
import { createJiti } from "jiti";
import type { AnyAction } from "gapmcp-core";
import { ActionRegistry, isActionArray, isActionDefinition } from "gapmcp-core";

type ModuleShape = {
  default?: unknown;
  actions?: unknown;
  registry?: unknown;
};

function fromValue(value: unknown, file: string): ActionRegistry | undefined {
  if (value instanceof ActionRegistry) return value;
  if (isActionArray(value)) return new ActionRegistry(value);
  if (isActionDefinition(value)) return new ActionRegistry([value]);
  if (value && typeof value === "object") {
    const shape = value as ModuleShape;
    if (shape.registry !== undefined) return fromValue(shape.registry, file);
    if (shape.actions !== undefined) return fromValue(shape.actions, file);
  }
  return undefined;
}

/**
 * Load an actions module. Supports `export default registry`, `export const
 * registry`, `export const actions = [...]`, and a single default action.
 */
export async function loadRegistry(file: string): Promise<ActionRegistry> {
  const absolute = path.resolve(file);
  const url = pathToFileURL(absolute).href;
  let imported: ModuleShape;

  if (absolute.endsWith(".ts") || absolute.endsWith(".mts") || absolute.endsWith(".cts")) {
    const jiti = createJiti(import.meta.url, { interopDefault: true, moduleCache: false });
    imported = (await jiti.import(absolute)) as ModuleShape;
  } else {
    imported = (await import(url)) as ModuleShape;
  }

  const registry =
    fromValue(imported.registry, file) ??
    fromValue(imported.actions, file) ??
    fromValue(imported.default, file) ??
    fromValue(imported, file);

  if (!registry) {
    throw new Error(
      `Could not find actions in ${file}. Export an ActionRegistry, an array of actions, or a single action (default or named "actions"/"registry").`,
    );
  }
  return registry;
}

export function collectActions(registry: ActionRegistry): AnyAction[] {
  return registry.list();
}
