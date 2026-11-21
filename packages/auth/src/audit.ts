import { mkdir, open } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEvent, AuditSink } from "gapmcp-core";
import { GapError, createId } from "gapmcp-core";

/** Input accepted by {@link createAuditEvent}. */
export type CreateAuditEventInput = Omit<AuditEvent, "id" | "timestamp"> & {
  /** Optional stable id; generated when omitted. */
  id?: string;
  /** ISO timestamp, epoch milliseconds, or a Date. Defaults to now. */
  timestamp?: string | number | Date;
};

/**
 * Fill in the generated fields of an audit event. Useful for sinks and tests
 * that want the same shape as the server pipeline.
 */
export function createAuditEvent(input: CreateAuditEventInput): AuditEvent {
  const { id, timestamp, ...rest } = input;
  const date =
    timestamp === undefined
      ? new Date()
      : timestamp instanceof Date
        ? timestamp
        : new Date(timestamp);
  return {
    ...rest,
    id: id ?? createId("evt"),
    timestamp: date.toISOString(),
  };
}

/** Options for {@link MemoryAuditLog}. */
export interface MemoryAuditLogOptions {
  /** Keep only the newest `max` events. Omit for an unbounded log. */
  max?: number;
}

/**
 * In-memory audit sink. Records are stored by reference; `list` returns a
 * shallow copy so callers cannot reorder or truncate the internal array.
 */
export class MemoryAuditLog implements AuditSink {
  /** Recorded events, oldest first. */
  events: AuditEvent[] = [];

  private readonly max: number | undefined;

  /** Accepts `{ max }` or a numeric shorthand for the bound. */
  constructor(options: MemoryAuditLogOptions | number = {}) {
    const max = typeof options === "number" ? options : options.max;
    if (max !== undefined && (!Number.isInteger(max) || max < 0)) {
      throw new GapError("Audit log max must be a non-negative integer.", {
        code: "INVALID_INPUT",
      });
    }
    this.max = max;
  }

  /** Append an event, evicting the oldest events when the bound is exceeded. */
  record(event: AuditEvent): void {
    if (this.max === 0) return;
    this.events.push(event);
    if (this.max !== undefined && this.events.length > this.max) {
      this.events.splice(0, this.events.length - this.max);
    }
  }

  /** Snapshot of the current events. */
  list(): AuditEvent[] {
    return [...this.events];
  }

  /** Remove every recorded event. */
  clear(): void {
    this.events.length = 0;
  }
}

/**
 * Append-only JSON Lines audit sink.
 *
 * Each event is written as one JSON object followed by `\n`. Writes are
 * serialized, the parent directory is created recursively, and the file is
 * opened with owner-only permissions. Call {@link close} to flush and release
 * the file handle.
 */
export class JsonlAuditLog implements AuditSink {
  private readonly filePath: string;
  private readonly ready: Promise<void>;
  private queue: Promise<void> = Promise.resolve();
  private handle: FileHandle | undefined;
  private closed = false;
  private closePromise: Promise<void> | undefined;

  constructor(path: string) {
    if (typeof path !== "string" || path.trim() === "") {
      throw new GapError("Audit log path must not be empty.", {
        code: "INVALID_INPUT",
      });
    }
    this.filePath = path;
    this.ready = mkdir(dirname(path), { recursive: true }).then(
      () => undefined,
    );
  }

  /** Queue one JSON line. Writes preserve call order. */
  record(event: AuditEvent): Promise<void> {
    if (this.closed) {
      return Promise.reject(
        new GapError("Audit log is closed.", {
          code: "INTERNAL",
          expose: false,
        }),
      );
    }

    const task = this.queue.then(() => this.append(event));
    // Keep the queue usable after a failed write; the caller still sees the
    // rejection on the promise returned below.
    this.queue = task.then(
      () => undefined,
      () => undefined,
    );
    return task;
  }

  /** Wait for pending writes and close the underlying file handle. */
  close(): Promise<void> {
    if (!this.closePromise) {
      this.closed = true;
      this.closePromise = (async () => {
        await this.queue;
        const handle = this.handle;
        this.handle = undefined;
        if (!handle) return;
        try {
          await handle.close();
        } catch (cause) {
          throw new GapError("Failed to close the audit log.", {
            code: "INTERNAL",
            expose: false,
            cause,
          });
        }
      })();
    }
    return this.closePromise;
  }

  private async append(event: AuditEvent): Promise<void> {
    let line: string;
    try {
      line = `${JSON.stringify(event)}\n`;
    } catch (cause) {
      throw new GapError("Audit event is not JSON-serializable.", {
        code: "INVALID_INPUT",
        cause,
      });
    }

    try {
      await this.ready;
      const handle = await this.getHandle();
      await handle.appendFile(line, "utf8");
    } catch (cause) {
      if (cause instanceof GapError) throw cause;
      throw new GapError("Failed to write the audit log.", {
        code: "INTERNAL",
        expose: false,
        cause,
      });
    }
  }

  private async getHandle(): Promise<FileHandle> {
    if (!this.handle) {
      this.handle = await open(this.filePath, "a", 0o600);
    }
    return this.handle;
  }
}
