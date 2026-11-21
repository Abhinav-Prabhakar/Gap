import type {
  ActionRegistry,
  ActionUiBinding,
  AnyAction,
  RiskLevel,
} from "gapmcp-core";

/** One UI-capable action in a DOM manifest. */
export interface DomActionBinding {
  name: string;
  scopes: string[];
  risk: RiskLevel;
  ui: ActionUiBinding;
}

/** A deterministic snapshot of every action that can be driven through the DOM. */
export interface DomManifest {
  version: 1;
  generatedAt: string;
  actions: DomActionBinding[];
}

/** Options for {@link buildDomManifest}. */
export interface BuildDomManifestOptions {
  /** Restrict the manifest to these action names. */
  include?: string[];
  /** Injectable clock, used to make snapshots reproducible in tests. */
  now?: () => number | Date | string;
}

function toIsoString(value: number | Date | string): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new TypeError("buildDomManifest received an invalid clock value.");
  }
  return date.toISOString();
}

function copyUi(ui: ActionUiBinding): ActionUiBinding {
  const copy: ActionUiBinding = {};
  if (typeof ui.route === "string") copy.route = ui.route;
  if (typeof ui.action === "string") copy.action = ui.action;
  if (ui.fields && typeof ui.fields === "object") {
    const fields: Record<string, string> = {};
    for (const key of Object.keys(ui.fields).sort()) {
      const selector = ui.fields[key];
      if (typeof selector === "string") fields[key] = selector;
    }
    copy.fields = fields;
  }
  if (typeof ui.submit === "string") copy.submit = ui.submit;
  if (typeof ui.result === "string") copy.result = ui.result;
  if (typeof ui.waitFor === "string") copy.waitFor = ui.waitFor;
  return copy;
}

function bindingFor(action: AnyAction): DomActionBinding {
  return {
    name: action.name,
    scopes: [...(action.scopes ?? [])],
    risk: action.risk ?? "low",
    ui: copyUi(action.ui ?? {}),
  };
}

/**
 * Build a deterministic DOM manifest from a registry. Only actions with a `ui`
 * binding are included; entries are sorted by name so two runs over the same
 * registry produce byte-identical JSON (given the same clock).
 */
export function buildDomManifest(
  registry: ActionRegistry,
  options: BuildDomManifestOptions = {},
): DomManifest {
  const include = options.include ? new Set(options.include) : undefined;
  const generatedAt = toIsoString(options.now ? options.now() : new Date());

  const actions = registry
    .list()
    .filter((action) => action.ui !== undefined)
    .filter((action) => !include || include.has(action.name))
    .map(bindingFor)
    .sort((a, b) => a.name.localeCompare(b.name));

  return { version: 1, generatedAt, actions };
}
