import { createId, normalizeError } from "gapmcp-core";
import type { CallReceipt, TaskManagerOptions, TaskRecord, TaskStatus } from "./types.js";

/** The work a task runs in the background. */
export type TaskRunner = (signal: AbortSignal) => Promise<{ result: unknown; receipt?: CallReceipt }>;

/** Input for {@link TaskManager.start}. */
export interface StartTaskInput {
  /** Explicit task id. Generated when omitted. */
  id?: string;
  action: string;
  principalId: string;
  tenantId?: string;
  traceId: string;
  approvalId?: string;
  input?: unknown;
  /** Id of the CallStore record this task updates when it settles. */
  callId?: string;
  run: TaskRunner;
}

/** Filter accepted by {@link TaskManager.list}. */
export interface TaskFilter {
  principalId?: string;
  tenantId?: string;
  action?: string;
  status?: TaskStatus | readonly TaskStatus[];
}

interface TaskEntry {
  record: TaskRecord;
  controller: AbortController;
}

function cloneTask(task: TaskRecord): TaskRecord {
  return {
    ...task,
    receipt: task.receipt ? { ...task.receipt } : undefined,
    error: task.error ? { ...task.error } : undefined,
  };
}

const TERMINAL: ReadonlySet<TaskStatus> = new Set(["completed", "failed", "cancelled"]);

/**
 * Owns background executions for actions declared with `task: true`.
 * Cancellation aborts the task signal and `close()` aborts every non-terminal
 * task before waiting for them to settle.
 */
export class TaskManager {
  readonly #tasks = new Map<string, TaskEntry>();
  readonly #pending = new Set<Promise<void>>();
  readonly #now: () => number;
  readonly #maxTasks: number;
  readonly #closeTimeoutMs: number;
  #closed = false;

  constructor(options: TaskManagerOptions = {}) {
    this.#now = options.now ?? Date.now;
    this.#maxTasks = options.maxTasks ?? 1_000;
    this.#closeTimeoutMs = options.closeTimeoutMs ?? 5_000;
    if (!Number.isInteger(this.#maxTasks) || this.#maxTasks <= 0) {
      throw new RangeError("TaskManager maxTasks must be a positive integer.");
    }
  }

  /** Number of retained tasks. */
  get size(): number {
    return this.#tasks.size;
  }

  /** Start a task and return its initial record. */
  start(input: StartTaskInput): TaskRecord {
    if (this.#closed) throw new Error("TaskManager is closed.");
    const now = this.#now();
    const timestamp = new Date(now).toISOString();
    const id = input.id ?? createId("task");
    const controller = new AbortController();
    const record: TaskRecord = {
      id,
      action: input.action,
      principalId: input.principalId,
      tenantId: input.tenantId,
      status: "working",
      createdAt: timestamp,
      updatedAt: timestamp,
      input: input.input,
      traceId: input.traceId,
      approvalId: input.approvalId,
      callId: input.callId,
    };
    this.#tasks.set(id, { record, controller });
    this.#prune();

    const promise = Promise.resolve()
      .then(async () => {
        if (controller.signal.aborted) throw abortError();
        const outcome = await input.run(controller.signal);
        if (controller.signal.aborted) {
          record.status = "cancelled";
          record.updatedAt = new Date(this.#now()).toISOString();
          return;
        }
        record.status = "completed";
        record.result = outcome.result;
        record.receipt = outcome.receipt;
        record.updatedAt = new Date(this.#now()).toISOString();
      })
      .catch((error: unknown) => {
        record.updatedAt = new Date(this.#now()).toISOString();
        if (controller.signal.aborted) {
          record.status = "cancelled";
          return;
        }
        record.status = "failed";
        const normalized = normalizeError(error);
        record.error = {
          code: normalized.code,
          message: normalized.expose ? normalized.message : "Internal error.",
        };
      })
      .finally(() => {
        this.#pending.delete(promise);
        this.#prune();
      });
    this.#pending.add(promise);
    return cloneTask(record);
  }

  /** Get a task by id. */
  get(id: string): TaskRecord | undefined {
    const entry = this.#tasks.get(id);
    return entry ? cloneTask(entry.record) : undefined;
  }

  /** List tasks, newest first. */
  list(filter: TaskFilter = {}): TaskRecord[] {
    const statuses =
      filter.status === undefined
        ? undefined
        : new Set<TaskStatus>(Array.isArray(filter.status) ? filter.status : [filter.status]);
    return [...this.#tasks.values()]
      .map((entry) => entry.record)
      .filter((record) => {
        if (filter.principalId !== undefined && record.principalId !== filter.principalId) return false;
        if (filter.tenantId !== undefined && record.tenantId !== filter.tenantId) return false;
        if (filter.action !== undefined && record.action !== filter.action) return false;
        if (statuses && !statuses.has(record.status)) return false;
        return true;
      })
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(cloneTask);
  }

  /**
   * Cancel a task. Cancelling a terminal task is a no-op and returns its final
   * record. The action is expected to observe the signal it received.
   */
  cancel(id: string): TaskRecord {
    const entry = this.#tasks.get(id);
    if (!entry) throw new Error(`Task "${id}" not found.`);
    if (!TERMINAL.has(entry.record.status) && !entry.controller.signal.aborted) {
      entry.controller.abort(abortError());
      if (entry.record.status === "working") {
        entry.record.status = "cancelled";
        entry.record.updatedAt = new Date(this.#now()).toISOString();
      }
    }
    return cloneTask(entry.record);
  }

  /** Abort all running tasks and wait for them to settle (bounded). */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    for (const entry of this.#tasks.values()) {
      if (!TERMINAL.has(entry.record.status) && !entry.controller.signal.aborted) {
        entry.controller.abort(abortError());
      }
    }
    if (this.#pending.size === 0) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const settled = Promise.allSettled([...this.#pending]).then(() => undefined);
    const timeout = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, this.#closeTimeoutMs);
    });
    try {
      await Promise.race([settled, timeout]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  #prune(): void {
    if (this.#tasks.size <= this.#maxTasks) return;
    const terminal = [...this.#tasks.values()]
      .filter((entry) => TERMINAL.has(entry.record.status))
      .sort((a, b) => a.record.createdAt.localeCompare(b.record.createdAt));
    for (const entry of terminal) {
      if (this.#tasks.size <= this.#maxTasks) break;
      this.#tasks.delete(entry.record.id);
    }
  }
}

function abortError(): DOMException {
  return new DOMException("Task cancelled.", "AbortError");
}
