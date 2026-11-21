import type { Logger, Span, Tracer } from "./types";

/**
 * Deterministic JSON with sorted keys. Used for argument hashing, approval
 * binding, idempotency keys and audit records.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value, new WeakSet<object>()));
}

function normalize(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new TypeError("Cannot canonicalize a circular structure.");
    seen.add(value);
    const result = value.map((item) => (item === undefined ? null : normalize(item, seen)));
    seen.delete(value);
    return result;
  }
  if (typeof value === "object") {
    if (seen.has(value)) throw new TypeError("Cannot canonicalize a circular structure.");
    seen.add(value);
    const record = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      const item = record[key];
      if (item === undefined) continue;
      result[key] = normalize(item, seen);
    }
    seen.delete(value);
    return result;
  }
  return String(value);
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes as BufferSource);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(bytes).digest("hex");
}

export async function hashValue(value: unknown): Promise<string> {
  return sha256Hex(canonicalJson(value));
}

export function createId(prefix: string): string {
  const raw =
    globalThis.crypto?.randomUUID?.().replace(/-/g, "").slice(0, 24) ??
    Math.random().toString(36).slice(2, 14) + Date.now().toString(36);
  return `${prefix}_${raw}`;
}

function scopeMatches(granted: string, required: string): boolean {
  if (granted === "*" || granted === required) return true;
  if (granted.endsWith(":*")) {
    const prefix = granted.slice(0, -1); // "invoices:"
    return required.startsWith(prefix);
  }
  if (granted.endsWith("*")) {
    return required.startsWith(granted.slice(0, -1));
  }
  return false;
}

/** Every required scope must be covered by a granted scope (wildcards allowed). */
export function hasScopes(granted: readonly string[] | undefined, required: readonly string[] | undefined): boolean {
  if (!required || required.length === 0) return true;
  const available = granted ?? [];
  return required.every((scope) => available.some((grant) => scopeMatches(grant, scope)));
}

export function missingScopes(granted: readonly string[] | undefined, required: readonly string[] | undefined): string[] {
  const available = granted ?? [];
  return (required ?? []).filter((scope) => !available.some((grant) => scopeMatches(grant, scope)));
}

function parsePath(path: string): string[] {
  return path
    .replace(/\[(\*|\d*)\]/g, (_match, inner: string) => `.${inner || "*"}`)
    .split(".")
    .map((part) => part.trim())
    .filter(Boolean);
}

/** Read a dot/bracket path from a value. Returns undefined when absent. */
export function deepGet(value: unknown, path: string): unknown {
  let current = value;
  for (const segment of parsePath(path)) {
    if (current === null || current === undefined) return undefined;
    if (Array.isArray(current)) {
      if (segment === "*") return current;
      const index = Number(segment);
      if (!Number.isInteger(index)) return undefined;
      current = current[index];
    } else if (typeof current === "object") {
      current = (current as Record<string, unknown>)[segment];
    } else {
      return undefined;
    }
  }
  return current;
}

export const REDACTED = "[REDACTED]";

function redactAt(value: unknown, segments: string[], index: number): unknown {
  if (index >= segments.length) return REDACTED;
  const segment = segments[index]!;
  if (Array.isArray(value)) {
    if (segment === "*") {
      return value.map((item) => redactAt(item, segments, index + 1));
    }
    const position = Number(segment);
    if (!Number.isInteger(position) || position < 0 || position >= value.length) return value;
    const copy = [...value];
    copy[position] = redactAt(copy[position], segments, index + 1);
    return copy;
  }
  if (typeof value !== "object" || value === null) return value;
  const record = value as Record<string, unknown>;
  if (segment === "*") {
    const copy: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(record)) {
      copy[key] = redactAt(item, segments, index + 1);
    }
    return copy;
  }
  if (!(segment in record)) return value;
  return { ...record, [segment]: redactAt(record[segment], segments, index + 1) };
}

/**
 * Deep-redact values at dot paths. Supports arrays with `items[].ssn` or
 * `items[*].ssn`. Never mutates the source object.
 */
export function redact<T>(value: T, paths: readonly string[] | undefined): T {
  if (!paths || paths.length === 0) return value;
  let result: unknown = value;
  for (const path of paths) {
    result = redactAt(result, parsePath(path), 0);
  }
  return result as T;
}

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const LEVELS: Record<Exclude<LogLevel, "silent">, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export function createLogger(level: LogLevel = "info", bindings: Record<string, unknown> = {}): Logger {
  const threshold = level === "silent" ? Infinity : LEVELS[level];
  const write = (lvl: Exclude<LogLevel, "silent">, message: string, args: unknown[]) => {
    if (LEVELS[lvl] < threshold) return;
    const line = {
      level: lvl,
      time: new Date().toISOString(),
      msg: message,
      ...bindings,
      ...(args.length ? { args } : {}),
    };
    const target = lvl === "error" ? console.error : lvl === "warn" ? console.warn : console.log;
    target(JSON.stringify(line));
  };
  return {
    debug: (message, ...args) => write("debug", message, args),
    info: (message, ...args) => write("info", message, args),
    warn: (message, ...args) => write("warn", message, args),
    error: (message, ...args) => write("error", message, args),
    child: (extra) => createLogger(level, { ...bindings, ...extra }),
  };
}

export const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
  child: () => silentLogger,
};

export const NOOP_SPAN: Span = {
  setAttribute: () => {},
  setAttributes: () => {},
  recordException: () => {},
  end: () => {},
};

export const NOOP_TRACER: Tracer = {
  startSpan: () => NOOP_SPAN,
};

/** Combine an optional parent signal with a timeout, without leaking timers. */
export function timeoutSignal(ms: number, parent?: AbortSignal): AbortSignal {
  if (!Number.isFinite(ms) || ms <= 0) return parent ?? new AbortController().signal;
  const timeout = AbortSignal.timeout(ms);
  return parent ? AbortSignal.any([parent, timeout]) : timeout;
}

export function isAbortError(error: unknown): boolean {
  return (
    (error instanceof DOMException && error.name === "AbortError") ||
    (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError"))
  );
}

/** Best-effort human duration, used in receipts and CLI output. */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.round(ms / 60_000)}m`;
}
