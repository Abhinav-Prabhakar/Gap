# gapmcp-importers

Turn existing surfaces into actions.

```ts
import { importOpenApi, scanNextRoutes } from "gapmcp-importers";

const actions = await importOpenApi({ spec, baseUrl: "https://api.example.com" });
const routes = await scanNextRoutes({ dir: "./app", baseUrl: "http://localhost:3000" });
```

OpenAPI 3.x (JSON/YAML, local `$ref`) and Next.js `app/**/route.ts` scanning. Generated actions are drafts: review descriptions, scopes and risk.

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
