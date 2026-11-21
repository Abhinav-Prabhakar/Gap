import type { IdempotencyRecord, IdempotencyStore } from "./types.js";

/** Options for {@link MemoryIdempotencyStore}. */
export interface MemoryIdempotencyStoreOptions {
  /** Default record lifetime. Defaults to ten minutes. */
  ttlMs?: number;
  /** Clock injection for tests. */
  now?: () => number;
  /** Maximum retained records. Expired records are pruned first. */
  maxEntries?: number;
}

const DEFAULT_TTL_MS = 10 * 60_000;
const DEFAULT_MAX_ENTRIES = 10_000;

function copyRecord<T>(record: IdempotencyRecord<T>): IdempotencyRecord<T> {
  return { ...record };
}

/**
 * In-memory idempotency cache. Values are opaque to the store; the server
 * stores completed {@link import("@modelcontextprotocol/sdk/types.js").CallToolResult}
 * objects so a replay is byte-for-byte identical to the original response.
 */
export class MemoryIdempotencyStore implements IdempotencyStore {
  readonly #records = new Map<string, IdempotencyRecord>();
  readonly #now: () => number;
  readonly #maxEntries: number;

  constructor(options: MemoryIdempotencyStoreOptions = {}) {
    this.#now = options.now ?? Date.now;
    this.#maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    if (!Number.isInteger(this.#maxEntries) || this.#maxEntries <= 0) {
      throw new Error("Idempotency maxEntries must be a positive integer.");
    }
  }

  /** Number of retained, unexpired records. */
  get size(): number {
    this.#prune();
    return this.#records.size;
  }

  get(key: string): IdempotencyRecord | undefined {
    const record = this.#records.get(key);
    if (!record) return undefined;
    if (record.expiresAt <= this.#now()) {
      this.#records.delete(key);
      return undefined;
    }
    return copyRecord(record);
  }

  set(key: string, record: IdempotencyRecord): void {
    const now = this.#now();
    if (record.expiresAt <= now) return;
    this.#records.set(key, { ...record, key });
    this.#prune();
  }

  delete(key: string): void {
    this.#records.delete(key);
  }

  /** Remove every record. Primarily useful in tests. */
  clear(): void {
    this.#records.clear();
  }

  #prune(): void {
    const now = this.#now();
    for (const [key, record] of this.#records) {
      if (record.expiresAt <= now) this.#records.delete(key);
    }
    if (this.#records.size <= this.#maxEntries) return;
    const oldest = [...this.#records.values()].sort((a, b) => a.createdAt - b.createdAt);
    for (const record of oldest) {
      if (this.#records.size <= this.#maxEntries) break;
      this.#records.delete(record.key);
    }
  }
}

/** Default idempotency TTL used for explicit and automatic keys. */
export const DEFAULT_IDEMPOTENCY_TTL_MS = DEFAULT_TTL_MS;
