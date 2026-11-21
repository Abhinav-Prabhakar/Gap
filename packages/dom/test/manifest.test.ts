import { describe, expect, it } from "vitest";
import { ActionRegistry, type AnyAction } from "gapmcp-core";
import { buildDomManifest } from "../src/index.js";

function action(overrides: Partial<AnyAction> & { name: string }): AnyAction {
  return {
    description: `Action ${overrides.name} used by DOM manifest tests.`,
    execute: async () => ({ ok: true }),
    ...overrides,
  };
}

describe("buildDomManifest", () => {
  it("includes only UI-capable actions, sorted by name", () => {
    const registry = new ActionRegistry([
      action({
        name: "zebra.update",
        scopes: ["zebra:write"],
        risk: "medium",
        ui: { route: "/zebra" },
      }),
      action({ name: "no.ui" }),
      action({
        name: "alpha.read",
        scopes: ["alpha:read"],
        risk: "low",
        ui: { action: "alpha" },
      }),
    ]);

    const manifest = buildDomManifest(registry, {
      now: () => new Date("2026-01-02T03:04:05.000Z"),
    });

    expect(manifest.version).toBe(1);
    expect(manifest.generatedAt).toBe("2026-01-02T03:04:05.000Z");
    expect(manifest.actions.map((binding) => binding.name)).toEqual([
      "alpha.read",
      "zebra.update",
    ]);
    expect(manifest.actions[0]).toEqual({
      name: "alpha.read",
      scopes: ["alpha:read"],
      risk: "low",
      ui: { action: "alpha" },
    });
  });

  it("honors the include list", () => {
    const registry = new ActionRegistry([
      action({ name: "a.one", ui: { route: "/one" } }),
      action({ name: "a.two", ui: { route: "/two" } }),
    ]);

    const manifest = buildDomManifest(registry, { include: ["a.two"] });
    expect(manifest.actions.map((binding) => binding.name)).toEqual(["a.two"]);
    expect(buildDomManifest(registry, { include: [] }).actions).toEqual([]);
  });

  it("normalizes ui fields deterministically and copies arrays", () => {
    const scopes = ["one", "two"];
    const registry = new ActionRegistry([
      action({
        name: "ui.normalize",
        scopes,
        risk: "high",
        ui: {
          route: "/normalize",
          action: "normalize",
          fields: { zebra: "#z", alpha: "input[name=alpha]" },
          submit: "button",
          result: "[data-result]",
          waitFor: "[data-ready]",
        },
      }),
    ]);

    const manifest = buildDomManifest(registry);
    expect(Object.keys(manifest.actions[0]!.ui.fields ?? {})).toEqual(["alpha", "zebra"]);
    expect(manifest.actions[0]!.scopes).toEqual(["one", "two"]);
    expect(manifest.actions[0]!.scopes).not.toBe(scopes);
    expect(manifest.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("returns an empty manifest for an empty registry", () => {
    const manifest = buildDomManifest(new ActionRegistry());
    expect(manifest).toMatchObject({ version: 1, actions: [] });
  });
});
