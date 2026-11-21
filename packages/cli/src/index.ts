#!/usr/bin/env node
import pc from "picocolors";
import { main } from "./program";

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(pc.red(`gap: ${message}`));
  if (process.env.GAP_DEBUG && error instanceof Error && error.stack) {
    console.error(pc.dim(error.stack));
  }
  process.exit(1);
});
