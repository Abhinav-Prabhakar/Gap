import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createRegistry } from "gapmcp-core";
import { createGapServer, MemoryApprovalStore } from "gapmcp-server";
import { apiKeyAuth, HmacApprovalGate, MemoryAuditLog } from "gapmcp-auth";
import { GapPolicy, parsePolicy } from "gapmcp-policy";
import type { AuditSink } from "gapmcp-core";
import { actions } from "./actions";

const port = Number(process.env.PORT ?? 4400);
const baseUrl = process.env.GAP_BASE_URL ?? `http://127.0.0.1:${port}`;
const token = process.env.GAP_TOKEN ?? "demo-key";
const readToken = process.env.GAP_READ_TOKEN ?? "demo-readonly-key";

const policy = new GapPolicy(
  parsePolicy(readFileSync(new URL("../policy.json", import.meta.url), "utf8")),
);

const audit = new MemoryAuditLog();
const approvals = new MemoryApprovalStore();

const gap = createGapServer({
  registry: createRegistry(...actions),
  name: "gap-demo-invoicing",
  version: "0.1.0",
  instructions:
    "An in-memory invoicing app. Use customers.list and invoices.list before mutating anything. invoices.send and invoices.delete require human approval; retry after approval.",
  baseUrl,
  auth: apiKeyAuth({
    keys: [
      {
        key: token,
        principal: { id: "usr_demo_owner", type: "user", name: "Demo Owner", scopes: ["*"] },
      },
      {
        key: readToken,
        principal: {
          id: "usr_demo_reader",
          type: "user",
          name: "Demo Read-only",
          scopes: ["invoices:read", "reports:read", "customers:read"],
        },
      },
    ],
  }),
  policy,
  approvalStore: approvals,
  approvals: new HmacApprovalGate({
    secret: process.env.GAP_APPROVAL_SECRET ?? "demo-approval-secret-change-me",
  }),
  audit: audit as AuditSink,
  handoffSecret: process.env.GAP_HANDOFF_SECRET ?? "demo-handoff-secret-change-me",
  onCall: (record) => {
    console.log(
      `[call] ${record.action ?? record.tool ?? "?"} ${record.principalId ?? ""} ` +
        `${record.durationMs != null ? `${record.durationMs}ms` : ""}`,
    );
  },
});

const http = createServer((req, res) => {
  if (req.url === "/" || req.url === "/info") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify(
        {
          name: "Gap demo invoicing app",
          mcp: `${baseUrl}/mcp`,
          metadata: `${baseUrl}/.well-known/oauth-protected-resource`,
          tokens: { owner: token, readOnly: readToken },
          inspector: "Run `pnpm gap inspect examples/demo/src/actions.ts --token demo-key` for the UI.",
          tools: gap.registry.list().map((action) => action.name),
        },
        null,
        2,
      ),
    );
    return;
  }
  void gap.handleNode(req, res);
});

http.listen(port, "127.0.0.1", () => {
  console.log("");
  console.log("  Gap demo invoicing app");
  console.log(`  MCP        ${baseUrl}/mcp`);
  console.log(`  Info       ${baseUrl}/info`);
  console.log(`  Owner key  ${token}`);
  console.log(`  Reader key ${readToken}`);
  console.log("");
  console.log("  Inspect    pnpm gap inspect examples/demo/src/actions.ts --token demo-key");
  console.log("");
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    http.close();
    void gap.close().then(() => process.exit(0));
  });
}
