import { describe, expect, it } from "vitest";
import path from "node:path";
import { loadRegistry } from "../src/load";

const fixture = (name: string) => path.join(import.meta.dirname, "fixtures", name);

describe("registry loader", () => {
  it("loads a named actions array from TypeScript", async () => {
    const registry = await loadRegistry(fixture("actions.ts"));
    expect(registry.list().map((action) => action.name)).toEqual(["fixture.ping"]);
  });

  it("loads an exported registry instance", async () => {
    const registry = await loadRegistry(fixture("registry.ts"));
    expect(registry.size).toBe(1);
    expect(registry.get("fixture.pong")?.description).toMatch(/Pong/);
  });

  it("loads a default action", async () => {
    const registry = await loadRegistry(fixture("single.ts"));
    expect(registry.list()[0]?.name).toBe("fixture.single");
  });

  it("explains what a module must export", async () => {
    await expect(loadRegistry(fixture("broken.ts"))).rejects.toThrow(/Could not find actions/);
  });

  it("rejects a missing file with a useful error", async () => {
    await expect(loadRegistry(fixture("missing.ts"))).rejects.toThrow();
  });
});
