import { createLogger, invalidInput } from "gapmcp-core";
import type { Logger, Span, Tracer } from "gapmcp-core";
import type {
  AttributeValue,
  Attributes,
  Exception,
  Span as OtelSpan,
  SpanStatus,
  Tracer as OtelTracer,
} from "@opentelemetry/api";

/** A primitive (or array of primitives) that can be stored on a recorded span. */
export type SpanAttributeValue =
  | string
  | number
  | boolean
  | Array<string | number | boolean>;

/** A serializable description of an exception attached to a span. */
export interface RecordedSpanError {
  name: string;
  message: string;
}

/**
 * A span captured by {@link MemoryTracer}. Timestamps are ISO 8601 strings and
 * `endTime`/`durationMs` are filled in when the span is ended.
 */
export interface RecordedSpan {
  name: string;
  attributes: Record<string, SpanAttributeValue>;
  status: "ok" | "error";
  startTime: string;
  endTime?: string;
  durationMs?: number;
  error?: RecordedSpanError;
}

/** Options for {@link MemoryTracer}. */
export interface MemoryTracerOptions {
  /**
   * Maximum number of spans retained. When the buffer is full the oldest span
   * is evicted. Defaults to 1000.
   */
  maxSpans?: number;
  /** Clock returning epoch milliseconds. Injectable for deterministic tests. */
  now?: () => number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function safeString(value: unknown): string {
  try {
    const json = JSON.stringify(value);
    return json ?? String(value);
  } catch {
    return String(value);
  }
}

function normalizeAttributeValue(
  value: unknown,
): SpanAttributeValue | undefined {
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    return value.map((entry) => {
      if (typeof entry === "string" || typeof entry === "boolean") return entry;
      if (typeof entry === "number") {
        return Number.isFinite(entry) ? entry : String(entry);
      }
      if (entry === null || entry === undefined) return "";
      return safeString(entry);
    });
  }
  if (value === null || value === undefined) return undefined;
  return safeString(value);
}

function normalizeAttributes(
  attributes: Record<string, unknown> | undefined,
): Record<string, SpanAttributeValue> {
  const normalized: Record<string, SpanAttributeValue> = {};
  for (const [key, value] of Object.entries(attributes ?? {})) {
    const mapped = normalizeAttributeValue(value);
    if (mapped !== undefined) normalized[key] = mapped;
  }
  return normalized;
}

function describeError(error: unknown): RecordedSpanError {
  if (error instanceof Error) {
    return { name: error.name || "Error", message: error.message };
  }
  if (isRecord(error)) {
    const name =
      typeof error.name === "string" && error.name.length > 0
        ? error.name
        : "Error";
    const message =
      typeof error.message === "string" ? error.message : safeString(error);
    return { name, message };
  }
  return {
    name: "Error",
    message: typeof error === "string" ? error : safeString(error),
  };
}

class MemorySpan implements Span {
  readonly #record: RecordedSpan;
  readonly #startMs: number;
  readonly #now: () => number;
  #ended = false;

  constructor(record: RecordedSpan, startMs: number, now: () => number) {
    this.#record = record;
    this.#startMs = startMs;
    this.#now = now;
  }

  setAttribute(key: string, value: string | number | boolean): void {
    const mapped = normalizeAttributeValue(value);
    if (mapped !== undefined) this.#record.attributes[key] = mapped;
  }

  setAttributes(attributes: Record<string, unknown>): void {
    for (const [key, value] of Object.entries(attributes)) {
      const mapped = normalizeAttributeValue(value);
      if (mapped !== undefined) this.#record.attributes[key] = mapped;
    }
  }

  recordException(error: unknown): void {
    this.#record.status = "error";
    this.#record.error = describeError(error);
  }

  end(): void {
    if (this.#ended) return;
    this.#ended = true;
    const endMs = this.#now();
    this.#record.endTime = new Date(endMs).toISOString();
    this.#record.durationMs = Math.max(0, endMs - this.#startMs);
  }
}

/**
 * An in-memory tracer that keeps a bounded list of spans for tests, local
 * inspection and replay diagnostics. It is safe to use in a request pipeline:
 * recording never throws and never logs.
 */
export class MemoryTracer implements Tracer {
  /** Captured spans, oldest first. The array is live and bounded. */
  readonly spans: RecordedSpan[] = [];

  readonly #maxSpans: number;
  readonly #now: () => number;

  /** Create a tracer retaining at most `maxSpans` finished or active spans. */
  constructor(options: MemoryTracerOptions = {}) {
    const maxSpans = options.maxSpans ?? 1000;
    if (!Number.isInteger(maxSpans) || maxSpans <= 0) {
      throw invalidInput("maxSpans must be a positive integer.", {
        maxSpans,
      });
    }
    this.#maxSpans = maxSpans;
    this.#now = options.now ?? Date.now;
  }

  /** Start and capture a span. The returned handle updates this record. */
  startSpan(name: string, attributes?: Record<string, unknown>): Span {
    const startMs = this.#now();
    const record: RecordedSpan = {
      name,
      attributes: normalizeAttributes(attributes),
      status: "ok",
      startTime: new Date(startMs).toISOString(),
    };
    this.spans.push(record);
    const overflow = this.spans.length - this.#maxSpans;
    if (overflow > 0) this.spans.splice(0, overflow);
    return new MemorySpan(record, startMs, () => this.#now());
  }

  /** A defensive copy of the captured spans. */
  getSpans(): RecordedSpan[] {
    return [...this.spans];
  }

  /** Discard every captured span. */
  clear(): void {
    this.spans.length = 0;
  }
}

type LogMethod = "debug" | "info" | "warn" | "error";

function safeLog(
  logger: Logger,
  level: LogMethod,
  message: string,
  data: Record<string, unknown>,
): void {
  try {
    logger[level](message, data);
  } catch {
    // Tracing must never break the operation it observes.
  }
}

class ConsoleSpan implements Span {
  readonly #name: string;
  readonly #logger: Logger;
  readonly #startMs = Date.now();
  #status: "ok" | "error" = "ok";
  #errorName: string | undefined;
  #ended = false;

  constructor(name: string, logger: Logger) {
    this.#name = name;
    this.#logger = logger;
  }

  // Attributes are intentionally not logged: they frequently contain user
  // identifiers, tokens or other values that must not reach stdout.
  setAttribute(_key: string, _value: string | number | boolean): void {}

  setAttributes(_attributes: Record<string, unknown>): void {}

  recordException(error: unknown): void {
    this.#status = "error";
    this.#errorName = describeError(error).name;
  }

  end(): void {
    if (this.#ended) return;
    this.#ended = true;
    const durationMs = Math.max(0, Date.now() - this.#startMs);
    safeLog(
      this.#logger,
      this.#status === "error" ? "warn" : "info",
      "span.end",
      {
        span: this.#name,
        status: this.#status,
        durationMs,
        ...(this.#errorName === undefined ? {} : { error: this.#errorName }),
      },
    );
  }
}

/**
 * A tracer that writes one line per finished span through a core `Logger`.
 * Attribute values are never logged, so tokens and raw PII cannot leak into
 * stdout. Logger failures are swallowed; tracing never breaks a call.
 */
export class ConsoleTracer implements Tracer {
  readonly #logger: Logger;

  /** Create a console tracer, optionally writing through a custom logger. */
  constructor(logger: Logger = createLogger("info")) {
    this.#logger = logger;
  }

  /** Start a console-logged span. Attribute values are deliberately ignored. */
  startSpan(name: string, _attributes?: Record<string, unknown>): Span {
    safeLog(this.#logger, "debug", "span.start", { span: name });
    return new ConsoleSpan(name, this.#logger);
  }
}

function toOtelValue(value: unknown): AttributeValue | undefined {
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : String(value);
  }
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    return value.map((entry) => {
      if (typeof entry === "string" || typeof entry === "boolean") return entry;
      if (typeof entry === "number") {
        return Number.isFinite(entry) ? entry : String(entry);
      }
      if (entry === null || entry === undefined) return "";
      return safeString(entry);
    });
  }
  if (value === null || value === undefined) return undefined;
  return safeString(value);
}

function toOtelAttributes(
  attributes: Record<string, unknown> | undefined,
): Attributes {
  const mapped: Attributes = {};
  for (const [key, value] of Object.entries(attributes ?? {})) {
    const converted = toOtelValue(value);
    if (converted !== undefined) mapped[key] = converted;
  }
  return mapped;
}

function toOtelException(error: unknown): Exception {
  if (typeof error === "string") return error;
  if (error instanceof Error) {
    return {
      name: error.name || "Error",
      message: error.message,
      ...(error.stack === undefined ? {} : { stack: error.stack }),
    };
  }
  if (isRecord(error)) {
    const name =
      typeof error.name === "string" && error.name.length > 0
        ? error.name
        : undefined;
    const message =
      typeof error.message === "string" ? error.message : undefined;
    const code =
      typeof error.code === "string" || typeof error.code === "number"
        ? error.code
        : undefined;
    if (message !== undefined) {
      return {
        ...(code === undefined ? {} : { code }),
        ...(name === undefined ? {} : { name }),
        message,
      };
    }
    if (name !== undefined) {
      return { name, ...(code === undefined ? {} : { code }) };
    }
    if (code !== undefined) return { code };
  }
  return safeString(error);
}

/** OTel's `SpanStatusCode.ERROR`, kept numeric so OTel stays type-only. */
const OTEL_ERROR = 2;

/**
 * Adapt an OpenTelemetry tracer to the Gap `Tracer` interface. Attribute
 * values are normalized to OTel-safe primitives; recorded exceptions set the
 * span status to error. `@opentelemetry/api` is imported for types only, so
 * this module has no runtime dependency on it.
 */
export function otelTracer(tracer: OtelTracer): Tracer {
  if (!tracer || typeof tracer.startSpan !== "function") {
    throw invalidInput("otelTracer requires an OpenTelemetry Tracer.", {
      issues: [
        {
          path: "(root)",
          message: "Expected a Tracer with a startSpan function.",
          code: "invalid_type",
        },
      ],
    });
  }

  return {
    startSpan(name: string, attributes?: Record<string, unknown>): Span {
      const otelSpan: OtelSpan = tracer.startSpan(name, {
        attributes: toOtelAttributes(attributes),
      });
      return {
        setAttribute(key, value): void {
          otelSpan.setAttribute(key, value);
        },
        setAttributes(next): void {
          otelSpan.setAttributes(toOtelAttributes(next));
        },
        recordException(error): void {
          const exception = toOtelException(error);
          otelSpan.recordException(exception);
          if (typeof otelSpan.setStatus === "function") {
            const message =
              typeof exception === "string" ? exception : exception.message;
            otelSpan.setStatus({
              code: OTEL_ERROR,
              ...(message === undefined ? {} : { message }),
            } as SpanStatus);
          }
        },
        end(): void {
          otelSpan.end();
        },
      };
    },
  };
}
