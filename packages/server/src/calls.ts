import type { CallRecord, CallStatus } from "./types.js";

/** Options for {@link CallStore}. */
export interface CallStoreOptions {
  /** Maximum retained calls. Defaults to 500. */
  limit?: number;
}

/** Filter accepted by {@link CallStore.list}. */
export interface CallFilter {
  limit?: number;
  principalId?: string;
  tenantId?: string;
  action?: string;
  status?: CallStatus | readonly CallStatus[];
}

function cloneCall(record: CallRecord): CallRecord {
  return {
    ...record,
    receipt: record.receipt ? { ...record.receipt } : undefined,
    approval: record.approval ? { ...record.approval } : undefined,
    error: record.error ? { ...record.error } : undefined,
    metadata: record.metadata ? { ...record.metadata } : undefined,
  };
}

/**
 * Fixed-size ring buffer of recent tool calls. The store upserts by id, so a
 * background task can replace its "task accepted" record with the completed
 * result without inflating the buffer.
 */
export class CallStore {
  readonly #limit: number;
  readonly #items: CallRecord[] = [];
  readonly #byId = new Map<string, CallRecord>();

  constructor(options: CallStoreOptions = {}) {
    const limit = options.limit ?? 500;
    if (!Number.isInteger(limit) || limit <= 0) {
      throw new RangeError("CallStore limit must be a positive integer.");
    }
    this.#limit = limit;
  }

  /** Maximum number of retained records. */
  get limit(): number {
    return this.#limit;
  }

  /** Current number of retained records. */
  get size(): number {
    return this.#items.length;
  }

  /**
   * Insert or replace a call. Replacing keeps the original position in the
   * ring, so a task's completion does not make it look like a new call.
   */
  put(record: CallRecord): CallRecord {
    const existing = this.#byId.get(record.id);
    if (existing) {
      const index = this.#items.indexOf(existing);
      const copy = cloneCall(record);
      if (index >= 0) this.#items[index] = copy;
      this.#byId.set(record.id, copy);
      return cloneCall(copy);
    }

    const copy = cloneCall(record);
    this.#items.push(copy);
    this.#byId.set(copy.id, copy);
    while (this.#items.length > this.#limit) {
      const removed = this.#items.shift();
      if (removed) this.#byId.delete(removed.id);
    }
    return cloneCall(copy);
  }

  /** Look up one call by id. */
  get(id: string): CallRecord | undefined {
    const record = this.#byId.get(id);
    return record ? cloneCall(record) : undefined;
  }

  /**
   * List calls, newest first. A number is accepted as a shorthand for
   * `{ limit }`, which is convenient for inspectors.
   */
  list(filter: CallFilter | number = {}): CallRecord[] {
    const normalized = typeof filter === "number" ? { limit: filter } : filter;
    const statuses =
      normalized.status === undefined
        ? undefined
        : new Set<CallStatus>(
            Array.isArray(normalized.status) ? normalized.status : [normalized.status],
          );

    const matches = [...this.#items]
      .reverse()
      .filter((record) => {
        if (normalized.principalId !== undefined && record.principalId !== normalized.principalId) {
          return false;
        }
        if (normalized.tenantId !== undefined && record.tenantId !== normalized.tenantId) return false;
        if (normalized.action !== undefined && record.action !== normalized.action) return false;
        if (statuses && !statuses.has(record.status)) return false;
        return true;
      })
      .map(cloneCall);

    if (normalized.limit !== undefined && normalized.limit >= 0) {
      return matches.slice(0, normalized.limit);
    }
    return matches;
  }

  /** Mark a receipt as undone and point it at the undo receipt. */
  markUndone(id: string, undoReceiptId: string, undoneAt = new Date().toISOString()): boolean {
    const record = this.#byId.get(id);
    if (!record) return false;
    record.undoneAt = undoneAt;
    record.undoReceiptId = undoReceiptId;
    return true;
  }

  /** Remove every retained call. */
  clear(): void {
    this.#items.length = 0;
    this.#byId.clear();
  }
}
