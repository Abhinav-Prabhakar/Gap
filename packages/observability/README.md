# gapmcp-observability

Tracing and replay.

```ts
import { MemoryTracer, ReplayRecorder, otelTracer } from "gapmcp-observability";

const tracer = new MemoryTracer();
const recorder = new ReplayRecorder({ redact: ["customer.ssn"] });
recorder.record({ action: "invoices.create", args, result, principalId: "usr_1", durationMs: 42 });
await recorder.replay(registry);
```

`otelTracer` wraps an OpenTelemetry tracer without making OTel a hard runtime dependency.

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
