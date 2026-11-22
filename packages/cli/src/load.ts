import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
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

function isRegistryLike(value: unknown): value is ActionRegistry {
  if (value instanceof ActionRegistry) return true;
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ActionRegistry>;
  return (
    typeof candidate.list === "function" &&
    typeof candidate.get === "function" &&
    typeof candidate.visibleTo === "function" &&
    typeof candidate.toToolDescriptors === "function"
  );
}

function fromValue(value: unknown, file: string): ActionRegistry | undefined {
  if (isRegistryLike(value)) return value;
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

  const isBun = typeof process !== "undefined" && Boolean(process.versions?.bun);
  if (absolute.endsWith(".ts") || absolute.endsWith(".mts") || absolute.endsWith(".cts")) {
    if (isBun) {
      // A `bun build --compile` binary cannot load jiti's Babel runtime. Ask
      // Bun's own bundler to compile the registry and its local imports into a
      // cache file inside the project, leaving npm packages external so normal
      // node_modules resolution still applies.
      const bun = (globalThis as {
        Bun?: {
          build?: (options: Record<string, unknown>) => Promise<{ outputs: Array<{ path: string }> }>;
        };
      }).Bun;
      if (!bun?.build) {
        imported = (await import(url)) as ModuleShape;
      } else {
        const cacheKey = createHash("sha256").update(absolute).digest("hex").slice(0, 16);
        const cacheDir = path.join(tmpdir(), "gap-cli-cache", cacheKey);
        const built = await bun.build({
          entrypoints: [absolute],
          outdir: cacheDir,
          target: "bun",
          format: "esm",
          naming: "[name]-[hash].[ext]",
        });
        const output = built.outputs[0];
        if (!output) throw new Error(`Bun did not produce a build for ${file}.`);
        imported = (await import(pathToFileURL(output.path).href)) as ModuleShape;
      }
    } else {
      const jiti = createJiti(import.meta.url, { interopDefault: true, moduleCache: false });
      imported = (await jiti.import(absolute)) as ModuleShape;
    }
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
