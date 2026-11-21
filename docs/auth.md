# Auth and identity

Gap never uses an ambient service account. Every action runs as a **principal**
that was authenticated on the request.

```ts
interface Principal {
  id: string;
  type?: "user" | "service" | "anonymous";
  tenantId?: string;
  scopes?: string[];
  email?: string;
  name?: string;
  metadata?: Record<string, unknown>;
}
```

Your action sees `ctx.principal` and must scope its data access by it. Gap
enforces that the principal has the action's declared scopes; it cannot know
which rows that principal owns.

## API keys

Good for internal tools, local development and machine-to-machine calls.

```ts
import { apiKeyAuth } from "gapmcp-auth";

const auth = apiKeyAuth({
  keys: [
    { key: process.env.AGENT_KEY!, principal: { id: "agent_ops", type: "service", scopes: ["*"] } },
    { key: process.env.READ_KEY!, principal: { id: "agent_reader", type: "service", scopes: ["invoices:read"] } },
  ],
});
```

Keys are compared in constant time and can be sent as `Authorization: Bearer
<key>` or `X-API-Key`. You can also pass a resolver function for database-backed
keys.

## JWT / OAuth 2.1

`jwtAuth` is an OAuth 2.1 **resource server**. It verifies signature, issuer,
audience and expiry against a local or remote JWKS, then maps claims to a
principal.

```ts
import { jwtAuth, protectedResourceMetadata } from "gapmcp-auth";

const auth = jwtAuth({
  issuer: "https://auth.example.com/",
  audience: "https://api.example.com/mcp",
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
});

// Served automatically at /.well-known/oauth-protected-resource
const metadata = protectedResourceMetadata({
  resource: "https://api.example.com/mcp",
  authorizationServers: ["https://auth.example.com"],
  scopesSupported: ["invoices:read", "invoices:write"],
});
```

Default claim mapping: `sub` → `id`, `scope` (space string) or `scp` (array) →
`scopes`, `tenant_id`/`tenantId` → `tenantId`, `email`, `name`. Override with
`mapClaims`; return `null` to reject a token.

Point clients at the metadata document (RFC 9728) so they can discover the
authorization server and required scopes. The server sends
`WWW-Authenticate: Bearer resource_metadata="…"` on 401.

## On-behalf-of token exchange

When your MCP server sits in front of another API, exchange the agent token for
a downscoped token instead of reusing a service credential:

```ts
import { exchangeToken } from "gapmcp-auth";

const { accessToken } = await exchangeToken({
  tokenEndpoint: "https://auth.example.com/oauth/token",
  subjectToken: ctx.principal.metadata?.accessToken as string,
  audience: "https://billing.internal",
  scope: ["invoices:write"],
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
});
```

This is RFC 8693. The downstream API should see the user, not your server.

## Approval gates

An approval is a signed grant bound to one action, one principal and the exact
arguments:

```ts
import { HmacApprovalGate } from "gapmcp-auth";

const gate = new HmacApprovalGate({ secret: process.env.APPROVAL_SECRET!, ttlMs: 10 * 60_000 });
```

- Token format: `v1.<base64url payload>.<base64url HMAC-SHA256>`.
- Payload includes `action`, `argsHash`, `approvedBy`, `iat`, `exp`, `nonce`.
- Verification re-hashes the arguments. Changing any value invalidates the
  grant.
- Expired, tampered, wrong-action, wrong-principal and malformed tokens are all
  rejected.

The default flow parks a call in the approval store and tells the agent to
retry after a human approves. If the MCP client supports elicitation and
`allowElicitation` is on, the server asks in-band instead.

## Audit

Every call emits an `AuditEvent`:

```ts
{
  id, timestamp, action, principalId, tenantId,
  decision: "allowed" | "denied" | "error" | "approval_required" | "dry_run",
  argsHash, resultHash, durationMs, scopes, approvalId, traceId,
  error?: { code, message }
}
```

Sinks: `MemoryAuditLog` (tests/inspector), `JsonlAuditLog` (append-only file),
or your own `AuditSink` (Kafka, ClickHouse, SIEM). Raw secrets and PII are never
recorded by default; only hashes.

## Tenancy

`tenantId` is copied onto the context. Every query should include it. If you
serve multiple tenants from one endpoint, derive `tenantId` from a verified
claim, never from a tool argument.
