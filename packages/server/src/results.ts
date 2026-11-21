import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { GapError } from "gapmcp-core";
import type { CallReceipt, GapErrorPayload, JsonObject } from "./types.js";

/** Check whether a value is a plain JSON object suitable for `structuredContent`. */
export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Human-readable rendering used for the mandatory text content block. */
export function toText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "OK";
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}

/** Build a text content block. */
export function textContent(text: string): { type: "text"; text: string } {
  return { type: "text", text };
}

/** Metadata attached to successful tool results. */
export interface ReceiptMeta {
  id: string;
  action: string;
  undoable: boolean;
  durationMs: number;
}

/** Convert a stored receipt into the compact `_meta["gap/receipt"]` payload. */
export function receiptMeta(receipt: CallReceipt): ReceiptMeta {
  return {
    id: receipt.id,
    action: receipt.action,
    undoable: receipt.undoable,
    durationMs: receipt.durationMs,
  };
}

/** Options for {@link successResult}. */
export interface SuccessResultOptions {
  value: unknown;
  receipt?: CallReceipt;
  traceId?: string;
  /** Use the value as structured content even when it is not an object. */
  forceStructured?: boolean;
  /** Additional structured content merged into the object result. */
  structuredExtras?: JsonObject;
}

/**
 * Build a successful tool result. Object values (and any value when
 * `forceStructured` is set) become `structuredContent`; primitives are text
 * only because MCP structured content must be a JSON object.
 */
export function successResult(options: SuccessResultOptions): CallToolResult {
  const { value, receipt, traceId } = options;
  const structured = options.forceStructured
    ? isJsonObject(value)
      ? value
      : { result: value }
    : isJsonObject(value)
      ? value
      : undefined;
  const merged = structured ? { ...structured, ...options.structuredExtras } : options.structuredExtras;

  const result: CallToolResult = { content: [textContent(toText(value))] };
  if (merged) result.structuredContent = merged;
  const meta: JsonObject = {};
  if (receipt) meta["gap/receipt"] = receiptMeta(receipt);
  if (traceId) meta["gap/traceId"] = traceId;
  if (Object.keys(meta).length > 0) result._meta = meta;
  return result;
}

/**
 * Build a successful tool result whose payload is already a structured object,
 * such as the approval-required and task-started responses.
 */
export function structuredResult(payload: JsonObject, text: string, traceId?: string): CallToolResult {
  const result: CallToolResult = {
    content: [textContent(text)],
    structuredContent: payload,
  };
  if (traceId) result._meta = { "gap/traceId": traceId };
  return result;
}

/** The safe, serialisable portion of a {@link GapError}. */
export function gapErrorPayload(error: GapError): GapErrorPayload {
  const message = error.expose ? error.message : "Internal error.";
  const payload: GapErrorPayload = {
    code: error.code,
    message,
    retryable: error.retryable,
  };
  if (error.expose && error.details !== undefined) payload.details = error.details;
  return payload;
}

/** Build an `isError: true` result with the standard `gapError` payload. */
export function errorResult(error: GapError, traceId?: string): CallToolResult {
  const payload = gapErrorPayload(error);
  const text = payload.details === undefined ? payload.message : `${payload.message}\n\n${toText(payload.details)}`;
  const result: CallToolResult = {
    content: [textContent(text)],
    isError: true,
    structuredContent: { gapError: payload },
  };
  if (traceId) result._meta = { "gap/traceId": traceId };
  return result;
}

/** Extract the receipt metadata from a tool result, if present. */
export function receiptMetaFromResult(result: unknown): ReceiptMeta | undefined {
  if (!isJsonObject(result)) return undefined;
  const meta = result._meta;
  if (!isJsonObject(meta)) return undefined;
  const receipt = meta["gap/receipt"];
  if (!isJsonObject(receipt)) return undefined;
  if (
    typeof receipt.id !== "string" ||
    typeof receipt.action !== "string" ||
    typeof receipt.undoable !== "boolean" ||
    typeof receipt.durationMs !== "number"
  ) {
    return undefined;
  }
  return {
    id: receipt.id,
    action: receipt.action,
    undoable: receipt.undoable,
    durationMs: receipt.durationMs,
  };
}

/** Type guard for a value that looks like a stored CallToolResult. */
export function isCallToolResult(value: unknown): value is CallToolResult {
  if (!isJsonObject(value)) return false;
  const content = value.content;
  if (!Array.isArray(content)) return false;
  return content.every((block) => isJsonObject(block) && typeof block.type === "string");
}
