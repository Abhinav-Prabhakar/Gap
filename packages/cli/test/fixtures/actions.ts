import { defineAction } from "gapmcp-core";
import { z } from "zod";

export const ping = defineAction({
  name: "fixture.ping",
  description: "Ping the fixture registry. Read-only.",
  input: z.object({}),
  output: z.object({ ok: z.boolean() }),
  execute: () => ({ ok: true }),
});

export const actions = [ping];
