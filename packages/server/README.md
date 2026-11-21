# gapmcp-server

The MCP server: Streamable HTTP and stdio, scope-filtered discovery, validation, policy, approvals, rate limits, idempotency, tasks, receipts and audit.

```bash
npm install gapmcp-server
```

```ts
import { createFetchHandler } from "gapmcp-server";
import { createRegistry } from "gapmcp-core";

const handler = createFetchHandler({ registry: createRegistry(...actions) });
export { handler as GET, handler as POST, handler as DELETE };
```

Node: `createGapServer(options).handleNode(req, res)`. Stdio: `createStdioServer(options)`.
Endpoints: `POST/GET/DELETE /mcp`, `GET /.well-known/oauth-protected-resource`, `GET /health`.

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
