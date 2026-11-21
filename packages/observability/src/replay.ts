import {
  GapError,
  createId,
  hashValue,
  invalidInput,
  redact,
  silentLogger,
} from "gapmcp-core";
import type {
  ActionContext,
  ActionRegistry,
  Principal,
  ValidationIssue,
} from "gapmcp-core";

/** A safe, JSON-friendly error captured on a recorded call or replay result. */
export interface RecordedCallError {
  code: string;
  message: string;
}

/** One tool invocation captured for later inspection or replay. */
export interface RecordedCall {
  id: string;
  /** ISO 8601 timestamp of the original call. */
  timestamp: string;
  action: string;
  args: unknown;
  result?: unknown;
  error?: RecordedCallError;
  principalId: string;
  tenantId?: string;
  durationMs: number;
}

/** The outcome of replaying a single recorded call. */
export interface ReplayResult {
  /** The id of the recorded call this result corresponds to. */
  id: string;
  action: string;
  ok: boolean;
  result?: unknown;
  error?: RecordedCallError;
  durationMs: number;
}

/** Options for constructing a {@link ReplayRecorder}. */
export interface ReplayRecorderOptions {
  /**
   * Dot paths redacted from arguments and results before they are stored.
   * Uses the same path syntax as core's `redact` (`items[].card.number`).
   */
  redact?: string[];
  /** Clock returning epoch milliseconds. Injectable for deterministic tests. */
  now?: () => number;
}

/** Options for {@link ReplayRecorder.replay}. */
export interface ReplayOptions {
  /** Identity to execute as. Defaults to the recorded principal id/tenant. */
  principal?: Principal;
  /** Value passed to the action context's `dryRun` flag. Defaults to false. */
  dryRun?: boolean;
}

interface ReplayFile {
  version: 1;
  redact: string[];
  calls: RecordedCall[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeString(value: unknown): string {
  try {
    const json = JSON.stringify(value);
    return json ?? String(value);
  } catch {
    return String(value);
  }
}

/**
 * Snapshot a value so later mutation by an action cannot change recorded
 * entries. Falls back to a JSON copy for values structured-clone rejects.
 */
function cloneValue<T>(value: T): T {
  try {
    return structuredClone(value);
  } catch {
    try {
      return JSON.parse(JSON.stringify(value)) as T;
    } catch {
      return value;
    }
  }
}

function toReplayError(error: unknown): RecordedCallError {
  if (error instanceof GapError) {
    return { code: error.code, message: error.message };
  }
  if (error instanceof Error) {
    return { code: "INTERNAL", message: error.message };
  }
  return {
    code: "INTERNAL",
    message: typeof error === "string" ? error : safeString(error),
  };
}

function pushIssue(
  issues: ValidationIssue[],
  path: string,
  message: string,
  code: string,
): void {
  issues.push({ path, message, code });
}

function normalizeRecordedCall(
  raw: unknown,
  path: string,
  issues: ValidationIssue[],
): RecordedCall | undefined {
  if (!isRecord(raw)) {
    pushIssue(issues, path, "Expected a recorded call object.", "invalid_type");
    return undefined;
  }

  let valid = true;
  const check = (condition: boolean, field: string, message: string, code: string): void => {
    if (condition) return;
    pushIssue(issues, `${path}.${field}`, message, code);
    valid = false;
  };

  check(
    typeof raw.id === "string" && raw.id.length > 0,
    "id",
    "Expected a non-empty string.",
    "invalid_value",
  );
  check(
    typeof raw.timestamp === "string" &&
      !Number.isNaN(Date.parse(raw.timestamp)),
    "timestamp",
    "Expected an ISO 8601 timestamp.",
    "invalid_value",
  );
  check(
    typeof raw.action === "string" && raw.action.length > 0,
    "action",
    "Expected a non-empty tool name.",
    "invalid_value",
  );
  check(
    typeof raw.principalId === "string" && raw.principalId.length > 0,
    "principalId",
    "Expected a non-empty principal id.",
    "invalid_value",
  );
  check(
    typeof raw.durationMs === "number" &&
      Number.isFinite(raw.durationMs) &&
      raw.durationMs >= 0,
    "durationMs",
    "Expected a non-negative finite number.",
    "invalid_value",
  );
  if (raw.tenantId !== undefined) {
    check(
      typeof raw.tenantId === "string",
      "tenantId",
      "Expected a string.",
      "invalid_type",
    );
  }

  let error: RecordedCallError | undefined;
  if (raw.error !== undefined) {
    if (
      !isRecord(raw.error) ||
      typeof raw.error.code !== "string" ||
      typeof raw.error.message !== "string"
    ) {
      pushIssue(
        issues,
        `${path}.error`,
        "Expected an object with string code and message fields.",
        "invalid_type",
      );
      valid = false;
    } else {
      error = { code: raw.error.code, message: raw.error.message };
    }
  }

  if (!valid) return undefined;

  const call: RecordedCall = {
    id: raw.id as string,
    timestamp: raw.timestamp as string,
    action: raw.action as string,
    args: raw.args,
    principalId: raw.principalId as string,
    durationMs: raw.durationMs as number,
  };
  if (typeof raw.tenantId === "string") call.tenantId = raw.tenantId;
  if ("result" in raw) call.result = raw.result;
  if (error) call.error = error;
  return call;
}

function validateRedactPaths(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): string[] {
  if (!Array.isArray(value)) {
    pushIssue(issues, path, "Expected an array of dot paths.", "invalid_type");
    return [];
  }
  const paths: string[] = [];
  value.forEach((entry, index) => {
    if (typeof entry !== "string" || entry.trim().length === 0) {
      pushIssue(
        issues,
        `${path}[${index}]`,
        "Expected a non-empty dot path.",
        "invalid_value",
      );
    } else {
      paths.push(entry);
    }
  });
  return paths;
}

/**
 * Records tool calls with optional argument/result redaction and replays them
 * against a registry. Replay executes sequentially in recorded order, passes a
 * real `ActionContext` with a fresh abort signal, and never mutates the stored
 * entries (arguments are cloned before the action sees them).
 */
export class ReplayRecorder {
  readonly #redactPaths: string[];
  readonly #now: () => number;
  readonly #calls: RecordedCall[] = [];

  constructor(options: ReplayRecorderOptions = {}) {
    this.#redactPaths = [...(options.redact ?? [])];
    this.#now = options.now ?? Date.now;
  }

  /**
   * Capture a call. The returned entry is a snapshot; mutating it does not
   * change what the recorder stores or replays.
   */
  record(call: Omit<RecordedCall, "id" | "timestamp">): RecordedCall {
    const stored: RecordedCall = {
      id: createId("call"),
      timestamp: new Date(this.#now()).toISOString(),
      action: call.action,
      args: this.#redactAndClone(call.args),
      principalId: call.principalId,
      durationMs: call.durationMs,
    };
    if (call.tenantId !== undefined) stored.tenantId = call.tenantId;
    if (call.result !== undefined) {
      stored.result = this.#redactAndClone(call.result);
    }
    if (call.error !== undefined) {
      stored.error = { code: call.error.code, message: call.error.message };
    }
    this.#calls.push(stored);
    return cloneValue(stored);
  }

  /** Snapshot of every recorded call, in insertion order. */
  entries(): RecordedCall[] {
    return cloneValue(this.#calls);
  }

  /** Serialize the recorder, including its redaction configuration. */
  toJSON(): string {
    const file: ReplayFile = {
      version: 1,
      redact: [...this.#redactPaths],
      calls: this.#calls,
    };
    return JSON.stringify(file);
  }

  /**
   * Restore a recorder from {@link ReplayRecorder.toJSON} output. Plain JSON
   * arrays of calls are accepted too for hand-written fixtures.
   *
   * @throws GapError `INVALID_INPUT` for malformed JSON or invalid entries.
   */
  static fromJSON(json: string): ReplayRecorder {
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw invalidInput("Replay data must be valid JSON.", {
        issues: [
          { path: "(root)", message: "Invalid JSON.", code: "invalid_json" },
        ],
      });
    }

    const issues: ValidationIssue[] = [];
    let rawCalls: unknown;
    let redactPaths: string[] = [];

    if (Array.isArray(parsed)) {
      rawCalls = parsed;
    } else if (isRecord(parsed)) {
      if (parsed.version !== undefined && parsed.version !== 1) {
        pushIssue(
          issues,
          "version",
          `Unsupported replay version ${String(parsed.version)}; expected 1.`,
          "invalid_value",
        );
      }
      if (parsed.redact !== undefined) {
        redactPaths = validateRedactPaths(parsed.redact, "redact", issues);
      }
      if (!Array.isArray(parsed.calls)) {
        pushIssue(
          issues,
          "calls",
          "Expected an array of recorded calls.",
          "invalid_type",
        );
      } else {
        rawCalls = parsed.calls;
      }
    } else {
      pushIssue(
        issues,
        "(root)",
        "Expected a replay file object or an array of calls.",
        "invalid_type",
      );
    }

    const calls: RecordedCall[] = [];
    if (Array.isArray(rawCalls)) {
      rawCalls.forEach((raw, index) => {
        const call = normalizeRecordedCall(raw, `calls[${index}]`, issues);
        if (call) calls.push(call);
      });
    }

    if (issues.length > 0) {
      throw invalidInput("Invalid replay data.", { issues });
    }

    const recorder = new ReplayRecorder({ redact: redactPaths });
    recorder.#calls.push(...calls);
    return recorder;
  }

  /**
   * Replay every recorded call against `registry`. Missing actions and thrown
   * errors become `ok: false` results and do not stop later calls.
   */
  async replay(
    registry: ActionRegistry,
    options: ReplayOptions = {},
  ): Promise<ReplayResult[]> {
    const results: ReplayResult[] = [];

    for (const call of this.#calls) {
      const action = registry.get(call.action);
      if (!action) {
        results.push({
          id: call.id,
          action: call.action,
          ok: false,
          error: {
            code: "NOT_FOUND",
            message: `Unknown action "${call.action}".`,
          },
          durationMs: 0,
        });
        continue;
      }

      const principal: Principal = options.principal ?? {
        id: call.principalId,
        ...(call.tenantId === undefined ? {} : { tenantId: call.tenantId }),
      };
      const tenantId = principal.tenantId ?? call.tenantId;
      const ctx: ActionContext = {
        principal,
        scopes: principal.scopes ?? [],
        dryRun: options.dryRun ?? false,
        signal: new AbortController().signal,
        traceId: createId("trace"),
        logger: silentLogger,
        ...(tenantId === undefined ? {} : { tenantId }),
      };

      const started = this.#now();
      try {
        const result = await action.execute(cloneValue(call.args), ctx);
        results.push({
          id: call.id,
          action: call.action,
          ok: true,
          ...(result === undefined
            ? {}
            : { result: this.#redactAndClone(result) }),
          durationMs: Math.max(0, this.#now() - started),
        });
      } catch (error) {
        results.push({
          id: call.id,
          action: call.action,
          ok: false,
          error: toReplayError(error),
          durationMs: Math.max(0, this.#now() - started),
        });
      }
    }

    return results;
  }

  #redactAndClone<T>(value: T): T {
    const copy = cloneValue(value);
    return this.#redactPaths.length === 0
      ? copy
      : redact(copy, this.#redactPaths);
  }
}

/**
 * Stable fingerprint of a recorded call's action and arguments, using core's
 * canonical hashing. Useful for deduplicating fixtures or naming snapshots.
 */
export function recordedCallFingerprint(call: RecordedCall): Promise<string> {
  return hashValue({ action: call.action, args: call.args });
}
