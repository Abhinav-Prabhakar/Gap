import { GapError } from "gapmcp-core";
import type { RateLimitResult, RateLimiter } from "./types.js";

/** Options for {@link TokenBucketRateLimiter}. */
export interface TokenBucketRateLimiterOptions {
  /** Maximum burst size, and the number of calls allowed per window. */
  limit: number;
  /** Refill window in milliseconds. */
  windowMs: number;
  /** Clock injection for tests. */
  now?: () => number;
}

interface Bucket {
  tokens: number;
  updatedAt: number;
}

const MAX_BUCKETS = 10_000;

function assertPositive(value: number, name: string): void {
  if (!Number.isFinite(value) || value <= 0) {
    throw new GapError(`${name} must be a positive number.`, { code: "INTERNAL", expose: false });
  }
}

/**
 * Continuous-refill token bucket limiter. Each key starts with `limit` tokens
 * and regains `limit / windowMs` tokens per millisecond.
 */
export class TokenBucketRateLimiter implements RateLimiter {
  /** Maximum burst size. */
  readonly limit: number;
  /** Refill window in milliseconds. */
  readonly windowMs: number;
  readonly #buckets = new Map<string, Bucket>();
  readonly #now: () => number;

  constructor(options: TokenBucketRateLimiterOptions) {
    assertPositive(options.limit, "Rate limit");
    assertPositive(options.windowMs, "Rate limit windowMs");
    this.limit = options.limit;
    this.windowMs = options.windowMs;
    this.#now = options.now ?? Date.now;
  }

  /** Number of tracked keys. */
  get size(): number {
    return this.#buckets.size;
  }

  consume(key: string, cost = 1): RateLimitResult {
    const amount = Number.isFinite(cost) && cost > 0 ? cost : 1;
    const now = this.#now();
    let bucket = this.#buckets.get(key);
    if (!bucket) {
      bucket = { tokens: this.limit, updatedAt: now };
      this.#buckets.set(key, bucket);
      this.#prune(now);
    } else {
      const elapsed = Math.max(0, now - bucket.updatedAt);
      bucket.tokens = Math.min(this.limit, bucket.tokens + (elapsed * this.limit) / this.windowMs);
      bucket.updatedAt = now;
    }

    if (bucket.tokens >= amount) {
      bucket.tokens -= amount;
      return {
        allowed: true,
        limit: this.limit,
        remaining: Math.floor(bucket.tokens),
        retryAfterMs: 0,
        resetAt: now,
      };
    }

    const missing = amount - bucket.tokens;
    const retryAfterMs = Math.max(1, Math.ceil((missing * this.windowMs) / this.limit));
    return {
      allowed: false,
      limit: this.limit,
      remaining: Math.floor(bucket.tokens),
      retryAfterMs,
      resetAt: now + retryAfterMs,
    };
  }

  /** Reset one key, or every key when `key` is omitted. */
  reset(key?: string): void {
    if (key === undefined) {
      this.#buckets.clear();
    } else {
      this.#buckets.delete(key);
    }
  }

  #prune(now: number): void {
    if (this.#buckets.size <= MAX_BUCKETS) return;
    for (const [key, bucket] of this.#buckets) {
      const full = bucket.tokens >= this.limit;
      if (full && now - bucket.updatedAt > this.windowMs) this.#buckets.delete(key);
      if (this.#buckets.size <= MAX_BUCKETS / 2) break;
    }
  }
}

/** A limiter that never rejects. Used when no rate limit is configured. */
export const unlimitedRateLimiter: RateLimiter = {
  consume(): RateLimitResult {
    return {
      allowed: true,
      limit: Number.POSITIVE_INFINITY,
      remaining: Number.POSITIVE_INFINITY,
      retryAfterMs: 0,
      resetAt: Date.now(),
    };
  },
};
