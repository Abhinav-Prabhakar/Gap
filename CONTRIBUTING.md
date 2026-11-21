# Contributing

Thanks for helping close the gap between agents and applications.

## Setup

```bash
pnpm install
pnpm test
pnpm typecheck
```

Node 20+ and pnpm 11 are required. There is intentionally **no CI**: lint,
typecheck, tests and builds run locally before a release.

## Repository layout

```
packages/core           action contract, registry, schema conversion
packages/server         MCP transport + call pipeline
packages/auth           identity, approval tokens, audit sinks
packages/policy         limits, confirmations, redaction
packages/observability  tracing and replay
packages/importers      OpenAPI and Next.js importers
packages/dom            DOM bindings and handoff links
packages/evals          tool-selection evals and linting
packages/testing        test harness
packages/cli            gap CLI and inspector
examples/demo           runnable invoicing app
python/                 Python port
go/                     Go port
```

## Adding an action

Actions belong in application code, not in Gap. For a new example or test,
define it with `defineAction` from `gapmcp-core`, give it a model-facing
description, declare scopes and risk, and add a test that calls it through
`gapmcp-testing`.

## Quality bar

- TypeScript strict; public exports documented.
- Every package has tests under `test/`.
- Errors that cross a boundary are `GapError`.
- No secrets in logs, fixtures, or commit history.
- New runtime dependencies need a strong justification; prefer the standard
  library and existing deps.

## Commits

Use imperative, scoped messages:

```
feat(server): add idempotency replay
fix(auth): reject approvals without a nonce
docs(readme): clarify the fallback ladder
```

## Releasing

1. Bump versions with `pnpm -r exec npm version patch --no-git-tag-version`.
2. `pnpm build && pnpm test && pnpm typecheck`.
3. `pnpm -r publish --access public`.
4. Tag `vX.Y.Z`, create a GitHub release, update the Homebrew and Scoop
   manifests.

By contributing you agree that your work is licensed under the MIT license.
