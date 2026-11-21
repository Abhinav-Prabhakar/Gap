# gapmcp-evals

Prove the agent picks the right tool before users find out.

```ts
import { runEvals, httpPlanner, lintRegistry } from "gapmcp-evals";

const report = await runEvals({ registry, cases, planner: httpPlanner({ endpoint, model }) });
console.log(report.summary());
console.log(report.confusion);
```

Subset argument matching, forbidden tools, confusion matrices, per-case JSON, and a description linter with ambiguous-sibling detection.

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
