import { describe, expect, it } from "vitest";
import type { Logger } from "gapmcp-core";
import type { Tracer as OtelTracer } from "@opentelemetry/api";
import { ConsoleTracer, MemoryTracer, otelTracer } from "../src/index";

describe("MemoryTracer", () => {
  it("records a span lifecycle, attributes and duration", () => {
    const base = 1_700_000_000_000;
    let tick = base;
    const tracer = new MemoryTracer({ now: () => tick });

    const span = tracer.startSpan("tool.call", {
      tool: "invoices.create",
      attempt: 1,
      cached: false,
      nested: { a: 1 },
      list: ["a", 2, true],
    });
    span.setAttribute("tenant", "acme");
    span.setAttributes({ ok: true, nullish: null });
    tick = base + 25;
    span.end();

    const recorded = tracer.spans[0]!;
    expect(recorded).toMatchObject({
      name: "tool.call",
      status: "ok",
      startTime: new Date(base).toISOString(),
      endTime: new Date(base + 25).toISOString(),
      durationMs: 25,
    });
    expect(recorded.attributes).toMatchObject({
      tool: "invoices.create",
      attempt: 1,
      cached: false,
      tenant: "acme",
      ok: true,
      list: ["a", 2, true],
    });
    expect(recorded.attributes.nested).toBe('{"a":1}');
    expect(recorded.attributes.nullish).toBeUndefined();
  });

  it("marks a span as errored when an exception is recorded", () => {
    let tick = 100;
    const tracer = new MemoryTracer({ now: () => tick });
    const span = tracer.startSpan("tool.fail");
    tick = 107;
    span.recordException(new TypeError("bad input"));
    span.end();

    const recorded = tracer.spans[0]!;
    expect(recorded.status).toBe("error");
    expect(recorded.error).toEqual({ name: "TypeError", message: "bad input" });
    expect(recorded.durationMs).toBe(7);
  });

  it("evicts the oldest spans when the buffer is bounded", () => {
    const tracer = new MemoryTracer({ max: 2 });
    tracer.startSpan("one").end();
    tracer.startSpan("two").end();
    tracer.startSpan("three").end();

    expect(tracer.spans.map((span) => span.name)).toEqual(["two", "three"]);
    expect(tracer.getSpans()).toHaveLength(2);
    expect(tracer.getSpans()).not.toBe(tracer.spans);
  });

  it("clears every captured span", () => {
    const tracer = new MemoryTracer();
    tracer.startSpan("one").end();
    tracer.clear();
    expect(tracer.spans).toHaveLength(0);
    expect(tracer.getSpans()).toEqual([]);
  });
});

describe("ConsoleTracer", () => {
  function recordingLogger(): {
    logger: Logger;
    calls: Array<{ level: string; message: string; args: unknown[] }>;
  } {
    const calls: Array<{ level: string; message: string; args: unknown[] }> = [];
    const push =
      (level: string) =>
      (message: string, ...args: unknown[]): void => {
        calls.push({ level, message, args });
      };
    return {
      calls,
      logger: {
        debug: push("debug"),
        info: push("info"),
        warn: push("warn"),
        error: push("error"),
      },
    };
  }

  it("logs finished spans without exposing attribute values", () => {
    const { logger, calls } = recordingLogger();
    const tracer = new ConsoleTracer(logger);
    const span = tracer.startSpan("tool.call", { token: "super-secret" });
    span.setAttributes({ password: "hunter2" });
    span.end();

    expect(calls.map((call) => call.level)).toEqual(["debug", "info"]);
    expect(calls[0]!.message).toBe("span.start");
    expect(calls[1]!.args[0]).toMatchObject({
      span: "tool.call",
      status: "ok",
    });
    expect(JSON.stringify(calls)).not.toContain("super-secret");
    expect(JSON.stringify(calls)).not.toContain("hunter2");
  });

  it("warns and records the error name for failed spans", () => {
    const { logger, calls } = recordingLogger();
    const tracer = new ConsoleTracer(logger);
    const span = tracer.startSpan("tool.fail");
    span.recordException(new Error("boom"));
    span.end();

    expect(calls.at(-1)).toMatchObject({
      level: "warn",
      message: "span.end",
    });
    expect(calls.at(-1)!.args[0]).toMatchObject({
      span: "tool.fail",
      status: "error",
      error: "Error",
    });
  });

  it("never throws when the logger throws", () => {
    const logger: Logger = {
      debug: () => {
        throw new Error("logger down");
      },
      info: () => {
        throw new Error("logger down");
      },
      warn: () => {
        throw new Error("logger down");
      },
      error: () => {
        throw new Error("logger down");
      },
    };
    const tracer = new ConsoleTracer(logger);

    expect(() => {
      const span = tracer.startSpan("tool.call");
      span.recordException(new Error("boom"));
      span.end();
    }).not.toThrow();
  });
});

describe("otelTracer", () => {
  it("maps attributes, exceptions and status to an OpenTelemetry tracer", () => {
    const recorded = {
      start: undefined as
        | { name: string; options?: { attributes?: Record<string, unknown> } }
        | undefined,
      single: [] as Array<[string, unknown]>,
      batches: [] as Array<Record<string, unknown>>,
      exceptions: [] as unknown[],
      statuses: [] as unknown[],
      ended: 0,
    };

    const fakeSpan = {
      setAttribute(key: string, value: unknown): void {
        recorded.single.push([key, value]);
      },
      setAttributes(attributes: Record<string, unknown>): void {
        recorded.batches.push(attributes);
      },
      recordException(exception: unknown): void {
        recorded.exceptions.push(exception);
      },
      setStatus(status: unknown): void {
        recorded.statuses.push(status);
      },
      end(): void {
        recorded.ended += 1;
      },
    };

    const fakeTracer = {
      startSpan(
        name: string,
        options?: { attributes?: Record<string, unknown> },
      ) {
        recorded.start = { name, options };
        return fakeSpan;
      },
    };

    const tracer = otelTracer(fakeTracer as unknown as OtelTracer);
    const span = tracer.startSpan("tool.call", {
      tool: "invoices.create",
      count: 2,
      nested: { a: 1 },
      empty: null,
    });

    expect(recorded.start).toEqual({
      name: "tool.call",
      options: {
        attributes: {
          tool: "invoices.create",
          count: 2,
          nested: '{"a":1}',
        },
      },
    });

    span.setAttribute("ok", true);
    span.setAttributes({ tenant: "acme", extra: { b: 2 } });
    expect(recorded.single).toEqual([["ok", true]]);
    expect(recorded.batches[0]).toEqual({
      tenant: "acme",
      extra: '{"b":2}',
    });

    span.recordException(new TypeError("bad input"));
    expect(recorded.exceptions[0]).toMatchObject({
      name: "TypeError",
      message: "bad input",
    });
    expect(recorded.statuses[0]).toMatchObject({
      code: 2,
      message: "bad input",
    });

    span.end();
    expect(recorded.ended).toBe(1);
  });
});
