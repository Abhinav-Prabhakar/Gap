import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { GapServer } from "./server.js";
import { createGapServer } from "./server.js";
import type { GapServerOptions } from "./types.js";

/**
 * Create a server bound to stdin/stdout for Claude Desktop, Claude Code, Cursor
 * and other local MCP clients.
 *
 * Stdio has no HTTP request to authenticate, so every call runs as the
 * anonymous principal with all scopes. That is appropriate for a process the
 * user launched themselves; do not bridge untrusted remote input into it.
 */
export async function createStdioServer(options: GapServerOptions): Promise<GapServer> {
  const server = createGapServer({ ...options, sessionMode: "stateless" });
  await server.connect(new StdioServerTransport());
  return server;
}
