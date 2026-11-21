# gapmcp-auth

Delegated identity and approvals.

- `apiKeyAuth` — constant-time API keys.
- `jwtAuth` — OAuth 2.1 resource server with JWKS, issuer and audience checks.
- `protectedResourceMetadata` / `bearerChallenge` — RFC 9728 discovery.
- `HmacApprovalGate` — approvals bound to a hash of the exact arguments.
- `exchangeToken` — RFC 8693 on-behalf-of token exchange.
- `MemoryAuditLog` / `JsonlAuditLog` — audit sinks.

```ts
import { apiKeyAuth } from "gapmcp-auth";

const auth = apiKeyAuth({
  keys: [{ key: process.env.GAP_TOKEN!, principal: { id: "agent", scopes: ["*"] } }],
});
```

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
