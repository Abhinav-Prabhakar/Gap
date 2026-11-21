# CLI

The `gap` CLI is the local development surface: scaffold, import, lint, eval,
inspect and serve.

```bash
npm install -D gapmcp-cli
npx gap --help
```

## `gap init`

```bash
gap init
gap init ./apps/agent --force
```

Creates `gap.actions.ts` (two working actions), `gap.server.ts`, a policy file,
`.env.example`, and a `package.json` when one is missing.

## `gap import openapi`

```bash
gap import openapi ./openapi.yaml --base-url https://api.example.com --out gap.openapi.ts
gap import openapi ./openapi.yaml --dry-run
```

Imports every operation as an action: parameters, request body, output schema,
risk by HTTP method, and a real `fetch` executor. The generated file loads the
spec at runtime, so re-import is optional. **Review descriptions and risk before
exposing it.**

## `gap tools`

```bash
gap tools ./gap.actions.ts
```

Prints the MCP tool surface with risk and scopes.

## `gap lint`

```bash
gap lint ./gap.actions.ts
gap lint ./gap.actions.ts --json
gap lint ./gap.actions.ts --strict
```

Exits non-zero on errors; `--strict` also fails on warnings. See
[Evals](./evals.md).

## `gap evals`

```bash
gap evals ./evals.json --registry ./gap.actions.ts --planner mock
OPENAI_API_KEY=... gap evals ./evals.json --registry ./gap.actions.ts --planner http
```

## `gap inspect`

```bash
gap inspect ./gap.actions.ts
gap inspect ./gap.actions.ts --policy ./gap.policy.json --token dev-token
```

Starts the inspector on `http://127.0.0.1:4400`:

- **Overview** — namespaces, tool counts, registry issues.
- **Tools** — descriptions, risk, scopes, flags and lint findings.
- **Playground** — calls the real `/mcp` endpoint with the real auth, policy,
  approvals and audit pipeline.
- **Calls** — principal, decision, duration, arguments and result.
- **Approvals** — pending high-risk calls; approve or deny inline.

The inspector is a development tool. It binds to `127.0.0.1` and shows
everything in the registry; do not deploy it.

## `gap serve`

```bash
# HTTP (default 0.0.0.0:4400)
gap serve ./gap.actions.ts --token "$GAP_TOKEN"

# stdio for Claude Desktop / Code / Cursor
gap serve ./gap.actions.ts --stdio

# Serverless-style stateless HTTP
gap serve ./gap.actions.ts --stateless
```

Options: `--policy`, `--base-url`, `--handoff-secret`, `--host`, `--port`.
Without `--token` (or `GAP_TOKEN`) the endpoint is anonymous with all scopes;
that is development-only.

## `gap dom`

```bash
gap dom ./gap.actions.ts --out gap.dom.json --runtime gap.dom.js
```

Compiles `ui` bindings into a manifest and browser runtime. See
[the fallback ladder](./fallback.md).

## `gap doctor`

```bash
gap doctor ./gap.actions.ts
```

Checks Node version, platform, CLI version and optionally loads/lints a
registry.
