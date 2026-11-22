import { ActionRegistry, defineAction } from "gapmcp-core";
import { z } from "zod";

const pong = defineAction({
  name: "fixture.pong",
  description: "Pong from the fixture registry. Read-only.",
  input: z.object({}),
  execute: () => ({ ok: true }),
});

export const registry = new ActionRegistry([pong]);
