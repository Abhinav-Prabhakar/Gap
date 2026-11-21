# Security

Gap is a security boundary between a probabilistic agent and real application
side effects. We take that seriously and welcome reports.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability. Email
`abhinavprabhakar06@gmail.com` with a description, a reproduction, and the
affected package/version. We aim to acknowledge within 72 hours and to ship a
fix or mitigation within 14 days for confirmed issues.

## Threat model

Gap assumes the model is untrusted. The following are in scope:

| Threat | Mitigation |
| --- | --- |
| Confused deputy — an agent reuses a user's broad token | Delegated principals, per-tool scopes, scope-filtered tool discovery |
| Approval argument swapping — a human approves one payload, the agent sends another | Approval grants are HMAC-signed over a canonical hash of the exact arguments |
| Replay of an old approval | Expiry, nonce, and principal/action binding |
| Prompt injection in tool output | Outputs are data; structured content is never treated as instructions. Redaction and provenance hooks are provided |
| Over-broad blast radius | Risk levels, confirmation policies, monetary/array limits, dry-run, idempotency, undo receipts |
| Token leakage in logs | Secrets and raw PII are never logged by default; audit records store hashes |
| SSRF through imported OpenAPI servers | Importers only call the configured base URL; review generated actions before deploying |
| Cross-tenant data access | `tenantId` is carried on the principal and context; application code must scope queries by it |

Out of scope: a compromised host process, a malicious MCP client with a valid
user token, and application code that ignores `ctx.principal`.

## Recommendations

- Use `jwtAuth` or `apiKeyAuth`; never expose an unauthenticated endpoint.
- Give every action the smallest scope that works and filter tools by scope.
- Set `risk: "high"` and `confirm: true` for anything externally visible.
- Use `GapPolicy` limits for money, rows and array sizes.
- Persist `MemoryAuditLog` output to append-only storage (`JsonlAuditLog` or
  your own `AuditSink`).
- Rotate `GAP_APPROVAL_SECRET` and `GAP_HANDOFF_SECRET`; they are bearer
  secrets.
- Keep the inspector bound to `127.0.0.1`.
