# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-11-22

The first public alpha.

### Added

- `gapmcp-core`: typed action contract (Zod 4 or JSON Schema), registry,
  schema conversion/validation, compound skills, tool search, canonical JSON,
  scoped helpers, redaction and structured errors.
- `gapmcp-server`: MCP Streamable HTTP + stdio, stateful/stateless sessions,
  scope-filtered discovery, policy, approvals, elicitation, rate limits,
  idempotency, tasks, receipts, undo, signed handoff, audit and OTel traces.
- `gapmcp-auth`: constant-time API keys, OAuth 2.1 resource server (JWT/JWKS),
  RFC 9728 metadata, RFC 8693 token exchange, HMAC approval grants and audit
  sinks.
- `gapmcp-policy`: deny/confirm/limits/dry-run/redaction policy DSL.
- `gapmcp-observability`: memory/console/OTel tracers and call replay.
- `gapmcp-importers`: OpenAPI 3.x (JSON/YAML) and Next.js route importers.
- `gapmcp-dom`: DOM manifest, zero-dependency browser runtime and signed
  handoff links.
- `gapmcp-evals`: subset argument scoring, forbidden tools, confusion matrix,
  mock/HTTP planners and a description linter.
- `gapmcp-testing`: action and end-to-end MCP test harness.
- `gapmcp-cli`: `gap init/import/lint/evals/inspect/serve/dom/doctor` and the
  local inspector.
- Python (`gapmcp`) and Go (`github.com/Abhinav-Prabhakar/Gap/go`) ports.
- Demo invoicing app, docs, security model and MIT license.
