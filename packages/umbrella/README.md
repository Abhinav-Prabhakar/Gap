# gapmcp

The umbrella package. One install, subpath exports for every layer.

```bash
npm install gapmcp zod
```

```ts
import { defineAction, createRegistry } from "gapmcp";
import { createFetchHandler } from "gapmcp/server";
import { apiKeyAuth } from "gapmcp/auth";
import { GapPolicy } from "gapmcp/policy";
```

Subpaths: `gapmcp/server`, `gapmcp/auth`, `gapmcp/policy`, `gapmcp/observability`, `gapmcp/dom`.

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
