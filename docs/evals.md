# Evals

An agent failing in production is usually not a reasoning failure. It picked
the wrong tool, or the right tool with the wrong arguments. Measure both before
shipping.

## Cases

```json
[
  {
    "name": "creates a draft invoice",
    "prompt": "Invoice Ada for one engineering retainer at $4,200, net 30.",
    "expectedTool": "invoices.create",
    "expectedArgs": {
      "customerId": "cus_ada",
      "lineItems": [{ "sku": "ENG-01", "quantity": 1 }]
    }
  },
  {
    "name": "does not send without being asked",
    "prompt": "Draft an invoice for Grace for two design sprints.",
    "expectedTool": "invoices.create",
    "forbiddenTools": ["invoices.send"]
  },
  {
    "name": "finds the customer first",
    "prompt": "What is Ada's billing email?",
    "expectedTool": "customers.get",
    "expectedArgs": { "id": "cus_ada" }
  }
]
```

Argument scoring is a **subset match**: expected keys must be present and equal;
extra model-supplied keys are reported but do not fail the case. Nested objects
are matched recursively; arrays must match exactly.

`forbiddenTools` catches the dangerous failure mode where the model does the
right thing *and* an extra thing.

## Run

```bash
# Deterministic harness check (the mock planner returns the expectation)
gap evals ./evals.json --registry ./actions.ts --planner mock

# Real model, OpenAI-compatible endpoint
OPENAI_API_KEY=... gap evals ./evals.json \
  --registry ./actions.ts \
  --planner http \
  --endpoint https://api.openai.com/v1 \
  --model gpt-4.1-mini

# Machine-readable
gap evals ./evals.json --registry ./actions.ts --planner mock --json
```

Programmatically:

```ts
import { runEvals, httpPlanner } from "gapmcp-evals";

const report = await runEvals({
  registry,
  cases,
  planner: httpPlanner({
    endpoint: "https://api.openai.com/v1",
    model: "gpt-4.1-mini",
    apiKey: process.env.OPENAI_API_KEY,
  }),
  scopes: ["invoices:read", "invoices:write"],
});

console.log(report.summary());
console.log(report.confusion);
console.log(report.toJSON());
```

## Confusion matrix

Rows are expected tools, columns are chosen tools. A hot row/column means two
tools are competing for the same intent. The fix is usually better
descriptions, not a bigger model.

```
expected \ chosen     invoices.create   invoices.send   (none)
invoices.create       14                2               1
invoices.send         1                 6               0
```

## Lint

`gap lint` combines the registry's contract checks with description quality:

- missing/short/long descriptions
- undescribed input fields
- risky actions without confirmation or idempotency
- destructive names without confirmation
- scope format
- descriptions that never state an outcome
- near-duplicate sibling tools (Jaccard similarity over name + description)
- estimated context cost

Score starts at 100, loses 20 per error and 5 per warning. Use `--strict` to
fail on warnings. There is no CI in this repo by design; run these locally
before a release.
