# gapmcp-testing

Test harness for actions and MCP servers.

```ts
import { callAction, startTestServer, callTool } from "gapmcp-testing";

await callAction(createInvoice, { customerId: "cus_ada", total: 42 });
const server = await startTestServer({ registry });
const result = await callTool({ url: server.url, name: "invoices.create", args });
await server.close();
```

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
