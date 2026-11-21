import type {
  ApprovalGate,
  ApprovalGrant,
  ApprovalRequest,
  IssuedApproval,
} from "gapmcp-core";
import { GapError, createId, hashValue } from "gapmcp-core";
import {
  base64UrlDecode,
  base64UrlDecodeToString,
  base64UrlEncode,
  encodeUtf8,
  hmacSha256,
  importHmacKey,
  isBase64Url,
  randomBytes,
  timingSafeEqualBytes,
  timingSafeEqualString,
} from "./crypto";
import { isRecord, nonEmptyString } from "./util";

/** Options for {@link HmacApprovalGate}. */
export interface HmacApprovalGateOptions {
  /** Shared secret used to sign approval tokens. */
  secret: string | Uint8Array;
  /** Lifetime applied when a request does not provide `ttlMs`. Defaults to 10 minutes. */
  ttlMs?: number;
  /** Clock in epoch milliseconds, injectable for deterministic tests. */
  now?: () => number;
}

interface ApprovalTokenPayload {
  id: string;
  action: string;
  argsHash: string;
  principalId: string;
  approvedBy: string;
  iat: number;
  exp: number;
  nonce: string;
}

const TOKEN_VERSION = "v1";
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const MAX_TOKEN_LENGTH = 8 * 1024;
const MAX_PAYLOAD_SEGMENT_LENGTH = 4 * 1024;
const MAX_SIGNATURE_SEGMENT_LENGTH = 128;
const HMAC_LENGTH = 32;

/**
 * Issue and verify compact human-approval grants:
 *
 * ```
 * v1.<base64url(json payload)>.<base64url(hmac-sha256)>
 * ```
 *
 * The payload binds the approval to the exact action, principal and canonical
 * argument hash. Verification recomputes the hash, rejects expired grants and
 * compares the signature in constant time. Tokens are never logged.
 */
export class HmacApprovalGate implements ApprovalGate {
  /** Default lifetime in milliseconds. */
  readonly ttlMs: number;

  private readonly now: () => number;
  private readonly keyPromise: Promise<CryptoKey>;

  constructor(options: HmacApprovalGateOptions) {
    const secret =
      typeof options.secret === "string"
        ? encodeUtf8(options.secret)
        : new Uint8Array(options.secret);
    if (secret.length === 0) {
      throw new GapError("Approval gate secret must not be empty.", {
        code: "INVALID_INPUT",
      });
    }

    const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new GapError("Approval ttlMs must be a positive number.", {
        code: "INVALID_INPUT",
      });
    }

    this.ttlMs = Math.floor(ttlMs);
    this.now = options.now ?? Date.now;
    this.keyPromise = importHmacKey(secret);
  }

  /** Create a signed grant for one action invocation. */
  async issue(request: ApprovalRequest): Promise<IssuedApproval> {
    const action = nonEmptyString(request.action);
    const principalId = nonEmptyString(request.principalId);
    if (!action || !principalId) {
      throw new GapError("Approval requires an action and principalId.", {
        code: "INVALID_INPUT",
      });
    }

    const ttlMs = request.ttlMs ?? this.ttlMs;
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new GapError("Approval ttlMs must be a positive number.", {
        code: "INVALID_INPUT",
      });
    }

    const current = this.now();
    if (!Number.isFinite(current)) {
      throw new GapError("Approval clock is unavailable.", {
        code: "INTERNAL",
        expose: false,
      });
    }
    const iat = Math.floor(current);
    const exp = iat + Math.max(1, Math.floor(ttlMs));

    let argsHash: string;
    try {
      argsHash = await hashValue(request.args);
    } catch (cause) {
      throw new GapError("Approval arguments must be JSON-serializable.", {
        code: "INVALID_INPUT",
        cause,
      });
    }

    const payload: ApprovalTokenPayload = {
      id: createId("apr"),
      action,
      argsHash,
      principalId,
      approvedBy: principalId,
      iat,
      exp,
      nonce: base64UrlEncode(randomBytes(16)),
    };

    const segment = base64UrlEncode(encodeUtf8(JSON.stringify(payload)));
    const signature = await this.sign(segment);

    return {
      token: `${TOKEN_VERSION}.${segment}.${signature}`,
      grant: {
        id: payload.id,
        action: payload.action,
        argsHash: payload.argsHash,
        approvedBy: payload.approvedBy,
        issuedAt: payload.iat,
        expiresAt: payload.exp,
      },
    };
  }

  /**
   * Verify a token against the current action, principal and arguments.
   * Returns `null` for any malformed, tampered, mismatched or expired token.
   */
  async verify(
    token: string,
    request: Omit<ApprovalRequest, "ttlMs">,
  ): Promise<ApprovalGrant | null> {
    if (
      typeof token !== "string" ||
      token.length === 0 ||
      token.length > MAX_TOKEN_LENGTH
    ) {
      return null;
    }

    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const version = parts[0];
    const payloadSegment = parts[1];
    const signatureSegment = parts[2];
    if (
      version !== TOKEN_VERSION ||
      !payloadSegment ||
      !signatureSegment ||
      payloadSegment.length > MAX_PAYLOAD_SEGMENT_LENGTH ||
      signatureSegment.length > MAX_SIGNATURE_SEGMENT_LENGTH ||
      !isBase64Url(payloadSegment) ||
      !isBase64Url(signatureSegment)
    ) {
      return null;
    }

    let providedSignature: Uint8Array;
    try {
      providedSignature = base64UrlDecode(signatureSegment);
    } catch {
      return null;
    }
    if (
      providedSignature.length !== HMAC_LENGTH ||
      base64UrlEncode(providedSignature) !== signatureSegment
    ) {
      return null;
    }

    let expectedSignature: Uint8Array;
    try {
      const key = await this.keyPromise;
      expectedSignature = await hmacSha256(
        key,
        encodeUtf8(`${TOKEN_VERSION}.${payloadSegment}`),
      );
    } catch {
      return null;
    }
    if (!timingSafeEqualBytes(providedSignature, expectedSignature)) {
      return null;
    }

    // Only parse JSON after the signature has been verified.
    let parsed: unknown;
    try {
      parsed = JSON.parse(base64UrlDecodeToString(payloadSegment));
    } catch {
      return null;
    }
    if (!isRecord(parsed)) return null;

    const payload = readPayload(parsed);
    if (!payload) return null;
    if (payload.exp <= payload.iat) return null;

    const current = this.now();
    if (!Number.isFinite(current)) return null;
    if (current >= payload.exp) return null;
    if (payload.action !== request.action) return null;
    if (payload.principalId !== request.principalId) return null;

    let expectedArgsHash: string;
    try {
      expectedArgsHash = await hashValue(request.args);
    } catch {
      return null;
    }
    if (!timingSafeEqualString(payload.argsHash, expectedArgsHash)) {
      return null;
    }

    return {
      id: payload.id,
      action: payload.action,
      argsHash: payload.argsHash,
      approvedBy: payload.approvedBy,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
    };
  }

  private async sign(payloadSegment: string): Promise<string> {
    const key = await this.keyPromise;
    const signature = await hmacSha256(
      key,
      encodeUtf8(`${TOKEN_VERSION}.${payloadSegment}`),
    );
    return base64UrlEncode(signature);
  }
}

function readPayload(
  value: Record<string, unknown>,
): ApprovalTokenPayload | null {
  const id = nonEmptyString(value.id);
  const action = nonEmptyString(value.action);
  const argsHash = nonEmptyString(value.argsHash);
  const principalId = nonEmptyString(value.principalId);
  const approvedBy = nonEmptyString(value.approvedBy);
  const nonce = nonEmptyString(value.nonce);
  const iat = value.iat;
  const exp = value.exp;

  if (
    !id ||
    !action ||
    !argsHash ||
    !principalId ||
    !approvedBy ||
    !nonce ||
    typeof iat !== "number" ||
    !Number.isSafeInteger(iat) ||
    typeof exp !== "number" ||
    !Number.isSafeInteger(exp)
  ) {
    return null;
  }

  return { id, action, argsHash, principalId, approvedBy, iat, exp, nonce };
}
