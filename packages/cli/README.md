# gapmcp-cli

The `gap` CLI and local inspector.

```bash
npm install -D gapmcp-cli

gap init
gap import openapi ./openapi.yaml --out gap.openapi.ts
gap lint ./gap.actions.ts
gap evals ./evals.json --registry ./gap.actions.ts --planner mock
gap inspect ./gap.actions.ts
gap serve ./gap.actions.ts --stdio
gap dom ./gap.actions.ts --runtime gap.dom.js
```

The inspector runs at `http://127.0.0.1:4400` with a live playground, call log and approval inbox.

Prefer no Node dependency? Install the standalone binary:

```bash
brew install Abhinav-Prabhakar/tap/gap
# scoop install gap · winget install AbhinavPrabhakar.Gap
```

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
