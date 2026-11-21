export const GAP_ERROR_CODES = [
  "UNAUTHENTICATED",
  "FORBIDDEN",
  "INVALID_INPUT",
  "NOT_FOUND",
  "CONFLICT",
  "RATE_LIMITED",
  "APPROVAL_REQUIRED",
  "POLICY_DENIED",
  "TIMEOUT",
  "UNAVAILABLE",
  "INTERNAL",
] as const;

export type GapErrorCode = (typeof GAP_ERROR_CODES)[number];

export interface GapErrorOptions {
  code: GapErrorCode;
  status?: number;
  details?: unknown;
  retryable?: boolean;
  expose?: boolean;
  cause?: unknown;
}

const DEFAULT_STATUS: Record<GapErrorCode, number> = {
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  INVALID_INPUT: 400,
  NOT_FOUND: 404,
  CONFLICT: 409,
  RATE_LIMITED: 429,
  APPROVAL_REQUIRED: 428,
  POLICY_DENIED: 403,
  TIMEOUT: 504,
  UNAVAILABLE: 503,
  INTERNAL: 500,
};

/**
 * The single error type that crosses the action boundary. Everything an agent
 * sees is derived from this, so messages stay safe and machine-readable.
 */
export class GapError extends Error {
  readonly code: GapErrorCode;
  readonly status: number;
  readonly details?: unknown;
  readonly retryable: boolean;
  readonly expose: boolean;

  constructor(message: string, options: GapErrorOptions) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "GapError";
    this.code = options.code;
    this.status = options.status ?? DEFAULT_STATUS[options.code];
    this.details = options.details;
    this.retryable =
      options.retryable ?? (options.code === "RATE_LIMITED" || options.code === "UNAVAILABLE");
    this.expose = options.expose ?? true;
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      status: this.status,
      retryable: this.retryable,
      ...(this.details === undefined ? {} : { details: this.details }),
    };
  }
}

export function isGapError(error: unknown): error is GapError {
  return error instanceof GapError;
}

export function unauthorized(message = "Authentication required."): GapError {
  return new GapError(message, { code: "UNAUTHENTICATED" });
}

export function forbidden(message = "You do not have permission to perform this action."): GapError {
  return new GapError(message, { code: "FORBIDDEN" });
}

export function invalidInput(message = "Invalid input.", details?: unknown): GapError {
  return new GapError(message, { code: "INVALID_INPUT", details });
}

export function notFound(message = "Not found."): GapError {
  return new GapError(message, { code: "NOT_FOUND" });
}

export function conflict(message = "Conflict.", details?: unknown): GapError {
  return new GapError(message, { code: "CONFLICT", details });
}

export function rateLimited(message = "Rate limit exceeded.", retryAfterMs?: number): GapError {
  return new GapError(message, {
    code: "RATE_LIMITED",
    details: retryAfterMs === undefined ? undefined : { retryAfterMs },
  });
}

export function approvalRequired(message = "This action requires human approval.", details?: unknown): GapError {
  return new GapError(message, { code: "APPROVAL_REQUIRED", details });
}

export function policyDenied(message = "Blocked by policy.", details?: unknown): GapError {
  return new GapError(message, { code: "POLICY_DENIED", details });
}

export function timeout(message = "The action timed out."): GapError {
  return new GapError(message, { code: "TIMEOUT" });
}

export function unavailable(message = "The action is temporarily unavailable."): GapError {
  return new GapError(message, { code: "UNAVAILABLE" });
}

export function internal(message = "Internal error.", cause?: unknown): GapError {
  return new GapError(message, { code: "INTERNAL", cause, expose: false });
}

/**
 * Turn anything thrown by application code into a GapError. Unknown errors are
 * deliberately opaque to clients and keep their detail in the server log.
 */
export function normalizeError(error: unknown): GapError {
  if (isGapError(error)) return error;
  if (error instanceof DOMException && error.name === "AbortError") {
    return timeout("The action was aborted or timed out.");
  }
  if (error instanceof Error) {
    return internal(error.message, error);
  }
  return internal(String(error));
}

export function statusForError(error: unknown): number {
  return isGapError(error) ? error.status : 500;
}
