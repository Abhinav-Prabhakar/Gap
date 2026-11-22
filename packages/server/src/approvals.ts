import { createId, GapError } from "gapmcp-core";
import type {
  ApprovalFilter,
  ApprovalRecord,
  ApprovalStatus,
  ApprovalStore,
  CreateApprovalInput,
  ResolveApprovalOptions,
} from "./types.js";

/** Options for {@link MemoryApprovalStore}. */
export interface MemoryApprovalStoreOptions {
  /** Default lifetime of a pending approval. Defaults to five minutes. */
  ttlMs?: number;
  /** Clock injection for tests. */
  now?: () => number;
  /** Maximum retained records. Oldest terminal records are evicted first. */
  maxEntries?: number;
}

const DEFAULT_TTL_MS = 5 * 60_000;
const DEFAULT_MAX_ENTRIES = 2_000;

function copyRecord(record: ApprovalRecord): ApprovalRecord {
  return {
    ...record,
    metadata: record.metadata ? { ...record.metadata } : undefined,
  };
}

function isExpired(record: ApprovalRecord, now: number): boolean {
  return (record.status === "pending" || record.status === "approved") && record.expiresAt <= now;
}

/**
 * In-memory {@link ApprovalStore}. Pending and approved records are deduplicated
 * by `(principalId, tenantId, action, argsHash)`, which makes retries idempotent
 * from the approver's point of view.
 */
export class MemoryApprovalStore implements ApprovalStore {
  readonly #records = new Map<string, ApprovalRecord>();
  readonly #ttlMs: number;
  readonly #now: () => number;
  readonly #maxEntries: number;

  constructor(options: MemoryApprovalStoreOptions = {}) {
    this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.#now = options.now ?? Date.now;
    this.#maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    if (!Number.isFinite(this.#ttlMs) || this.#ttlMs <= 0) {
      throw new GapError("Approval ttlMs must be a positive number.", { code: "INTERNAL", expose: false });
    }
    if (!Number.isInteger(this.#maxEntries) || this.#maxEntries <= 0) {
      throw new GapError("Approval maxEntries must be a positive integer.", { code: "INTERNAL", expose: false });
    }
  }

  /** Number of retained records, including terminal records. */
  get size(): number {
    return this.#records.size;
  }

  create(input: CreateApprovalInput): ApprovalRecord {
    const now = this.#now();
    this.#expire(now);

    const existing = [...this.#records.values()].find(
      (record) =>
        record.principalId === input.principalId &&
        record.tenantId === input.tenantId &&
        record.action === input.action &&
        record.argsHash === input.argsHash &&
        (record.status === "pending" || record.status === "approved") &&
        record.expiresAt > now,
    );
    if (existing) return copyRecord(existing);

    const ttlMs = input.ttlMs ?? this.#ttlMs;
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new GapError("Approval ttlMs must be a positive number.", { code: "INVALID_INPUT" });
    }

    const record: ApprovalRecord = {
      id: createId("apr"),
      principalId: input.principalId,
      tenantId: input.tenantId,
      action: input.action,
      argsHash: input.argsHash,
      status: "pending",
      createdAt: now,
      expiresAt: now + ttlMs,
      args: input.args,
      metadata: input.metadata ? { ...input.metadata } : undefined,
    };
    this.#records.set(record.id, record);
    this.#prune();
    return copyRecord(record);
  }

  get(id: string): ApprovalRecord | undefined {
    const record = this.#records.get(id);
    if (!record) return undefined;
    this.#expire(this.#now());
    return copyRecord(record);
  }

  list(filter: ApprovalFilter = {}): ApprovalRecord[] {
    this.#expire(this.#now());
    const statuses =
      filter.status === undefined
        ? undefined
        : new Set<ApprovalStatus>(Array.isArray(filter.status) ? filter.status : [filter.status]);

    return [...this.#records.values()]
      .filter((record) => {
        if (filter.principalId !== undefined && record.principalId !== filter.principalId) return false;
        if (filter.tenantId !== undefined && record.tenantId !== filter.tenantId) return false;
        if (filter.action !== undefined && record.action !== filter.action) return false;
        if (filter.argsHash !== undefined && record.argsHash !== filter.argsHash) return false;
        if (statuses && !statuses.has(record.status)) return false;
        return true;
      })
      .sort((a, b) => a.createdAt - b.createdAt)
      .map(copyRecord);
  }

  approve(id: string, options: ResolveApprovalOptions = {}): ApprovalRecord {
    const record = this.#require(id);
    const now = this.#now();
    this.#expire(now);
    if (record.status === "expired") {
      throw new GapError("This approval request has expired.", { code: "CONFLICT", details: { approvalId: id } });
    }
    if (record.status === "consumed") {
      throw new GapError("This approval has already been consumed.", { code: "CONFLICT", details: { approvalId: id } });
    }
    if (record.status === "denied") {
      throw new GapError("This approval was denied.", { code: "CONFLICT", details: { approvalId: id } });
    }
    if (record.status === "pending") {
      record.status = "approved";
      record.approvedAt = now;
      record.approvedBy = options.actor ?? "unknown";
    }
    return copyRecord(record);
  }

  deny(id: string, options: ResolveApprovalOptions = {}): ApprovalRecord {
    const record = this.#require(id);
    const now = this.#now();
    this.#expire(now);
    if (record.status === "expired") {
      throw new GapError("This approval request has expired.", { code: "CONFLICT", details: { approvalId: id } });
    }
    if (record.status === "consumed") {
      throw new GapError("This approval has already been consumed.", { code: "CONFLICT", details: { approvalId: id } });
    }
    if (record.status !== "denied") {
      record.status = "denied";
      record.deniedAt = now;
      record.deniedBy = options.actor ?? "unknown";
      record.reason = options.reason;
    }
    return copyRecord(record);
  }

  consume(id: string): ApprovalRecord {
    const record = this.#require(id);
    const now = this.#now();
    this.#expire(now);
    if (record.status !== "approved") {
      throw new GapError(
        record.status === "pending"
          ? "This approval has not been granted yet."
          : `This approval cannot be consumed while it is ${record.status}.`,
        { code: "CONFLICT", details: { approvalId: id, status: record.status } },
      );
    }
    if (record.expiresAt <= now) {
      record.status = "expired";
      throw new GapError("This approval request has expired.", { code: "CONFLICT", details: { approvalId: id } });
    }
    record.status = "consumed";
    record.consumedAt = now;
    return copyRecord(record);
  }

  /** Remove every record. Primarily useful in tests. */
  clear(): void {
    this.#records.clear();
  }

  #require(id: string): ApprovalRecord {
    const record = this.#records.get(id);
    if (!record) throw new GapError("Approval not found.", { code: "NOT_FOUND", details: { approvalId: id } });
    return record;
  }

  #expire(now: number): void {
    for (const record of this.#records.values()) {
      if (isExpired(record, now)) record.status = "expired";
    }
  }

  #prune(): void {
    if (this.#records.size <= this.#maxEntries) return;
    const terminal = [...this.#records.values()]
      .filter((record) => record.status === "consumed" || record.status === "denied" || record.status === "expired")
      .sort((a, b) => a.createdAt - b.createdAt);
    for (const record of terminal) {
      if (this.#records.size <= this.#maxEntries) break;
      this.#records.delete(record.id);
    }
  }
}
