# Deployment

Gap runs inside your application process. Payloads, database access and domain
logic never leave your infrastructure.

## HTTP modes

| Mode | Use when | Trade-off |
| --- | --- | --- |
| `stateful` (default) | Long-lived Node server | Sessions, resumable streams, in-memory approvals/tasks |
| `stateless` | Serverless, edge, multiple replicas | One server per request; external stores required for approvals/tasks |

```ts
const gap = createGapServer({ registry, sessionMode: "stateless" });
```

For Next.js:

```ts
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const GET = createFetchHandler(options);
export const POST = createFetchHandler(options);
export const DELETE = createFetchHandler(options);
```

## State

The default `MemoryApprovalStore`, `MemoryIdempotencyStore`, rate limiter,
`TaskManager` and `CallStore` are per-process. That is fine for one replica and
local use.

For multi-replica production, implement the interfaces with Redis/Postgres:

- approvals must be shared so a human can approve on one replica and the agent
  can retry on another;
- idempotency must be shared and use an atomic set-if-absent;
- rate limits must be shared or enforced at the gateway;
- tasks need a durable queue and a result store;
- call records and audit belong in append-only storage.

`HmacApprovalGate` tokens are stateless and work across replicas as long as the
secret is shared.

## Auth at the edge

Terminate TLS and, if you use an API gateway, let it validate the JWT, then pass
the token through so `jwtAuth` can still verify audience and map claims. Do not
strip the `Authorization` header. Serve
`/.well-known/oauth-protected-resource` and keep it consistent with the public
`resource` URL.

## Reverse proxy

- Forward `Mcp-Session-Id`.
- Disable response buffering for `text/event-stream`.
- Set read timeouts above your longest task.
- Cap request bodies (Gap defaults to 1 MB).

## Docker

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile --prod
COPY . .
RUN pnpm build
ENV PORT=4400
EXPOSE 4400
CMD ["node", "dist/server.js"]
```

## Observability

- Pass an OTel `Tracer` via `otelTracer(tracer)` for spans.
- Send `AuditSink` events to SIEM/ClickHouse/Kafka.
- Export call records or use `onCall` to feed metrics.
- Alert on approval-required spikes, policy denials, rate limits and undo use.

## Health and shutdown

`GET /health` is unauthenticated. On shutdown, call `gap.close()` to close
transports, abort running tasks and flush audit sinks.

## Production checklist

- [ ] Auth configured; no anonymous endpoint.
- [ ] Scopes declared on every action and filtered at discovery.
- [ ] `high`/`critical` actions require confirmation.
- [ ] Policy limits for money, rows and arrays.
- [ ] Shared approval, idempotency and rate-limit stores.
- [ ] Audit persisted and monitored.
- [ ] Handoff and approval secrets rotated.
- [ ] Inspector not deployed.
- [ ] Evals and lint run locally before release.
