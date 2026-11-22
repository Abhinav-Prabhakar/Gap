import { defineAction } from "gapmcp-core";
import { z } from "zod";

export default defineAction({
  name: "fixture.single",
  description: "A single default action. Read-only.",
  input: z.object({}),
  execute: () => ({ ok: true }),
});
