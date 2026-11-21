# gapmcp-dom

The fallback ladder: semantic DOM bindings and signed human handoff.

```ts
import { buildDomManifest, renderDomRuntime, createHandoffUrl } from "gapmcp-dom";

const manifest = buildDomManifest(registry);
const runtime = renderDomRuntime(); // inject into the page
const url = await createHandoffUrl({ baseUrl, action: "invoices.create", args, secret });
```

Bindings use `data-gap-action` and CSS field selectors, so a browser agent can act on intent instead of pixels.

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
