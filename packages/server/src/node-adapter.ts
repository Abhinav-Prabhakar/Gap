import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { jsonResponse } from "./http-utils.js";

/** Minimal interface required by the Node adapter. */
export interface NodeFetchTarget {
  fetch(request: Request): Promise<Response>;
}

function requestProtocol(req: IncomingMessage): string {
  const socket = req.socket as IncomingMessage["socket"] & { encrypted?: boolean };
  if (socket.encrypted) return "https";
  const forwarded = req.headers["x-forwarded-proto"];
  const value = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  const first = value?.split(",")[0]?.trim();
  return first === "https" ? "https" : "http";
}

function requestUrl(req: IncomingMessage): URL {
  const host = req.headers.host ?? "localhost";
  const raw = req.url ?? "/";
  if (/^https?:\/\//i.test(raw)) return new URL(raw);
  return new URL(raw, `${requestProtocol(req)}://${host}`);
}

function requestHeaders(req: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const entry of value) headers.append(name, entry);
    } else {
      headers.set(name, value);
    }
  }
  return headers;
}

function toRequest(req: IncomingMessage): Request {
  const method = (req.method ?? "GET").toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";
  const init: RequestInit & { duplex?: "half" } = {
    method,
    headers: requestHeaders(req),
  };
  if (hasBody) {
    init.body = Readable.toWeb(req) as unknown as ReadableStream<Uint8Array>;
    init.duplex = "half";
  }
  return new Request(requestUrl(req), init);
}

function writeHead(res: ServerResponse, response: Response): void {
  const headers: Record<string, string | string[]> = {};
  response.headers.forEach((value, name) => {
    if (name.toLowerCase() === "set-cookie") return;
    headers[name] = value;
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) headers["set-cookie"] = cookies;
  res.writeHead(response.status, headers);
  res.flushHeaders();
}

async function waitForDrain(res: ServerResponse): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const cleanup = () => {
      res.off("drain", onDrain);
      res.off("close", onClose);
      res.off("error", onError);
    };
    const onDrain = () => {
      cleanup();
      resolve();
    };
    const onClose = () => {
      cleanup();
      resolve();
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    res.once("drain", onDrain);
    res.once("close", onClose);
    res.once("error", onError);
  });
}

/**
 * Convert a Node `IncomingMessage` into a web `Request`, run the server, and
 * stream the response back. SSE frames are written to the socket as they
 * arrive; the response body is never buffered in full.
 */
export async function handleNodeRequest(
  target: NodeFetchTarget,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  req.socket.setNoDelay?.(true);
  const method = (req.method ?? "GET").toUpperCase();
  let response: Response;
  try {
    response = await target.fetch(toRequest(req));
  } catch (error) {
    if (!res.headersSent) {
      const failure = jsonResponse(500, { error: "internal_error" });
      writeHead(res, failure);
      res.end(await failure.text());
    } else {
      res.destroy(error instanceof Error ? error : undefined);
    }
    return;
  }

  if (res.destroyed) {
    await response.body?.cancel().catch(() => undefined);
    return;
  }
  writeHead(res, response);

  if (method === "HEAD" || !response.body || response.status === 204 || response.status === 304) {
    await response.body?.cancel().catch(() => undefined);
    res.end();
    return;
  }

  const reader = response.body.getReader();
  let cancelled = false;
  const onClose = () => {
    if (res.writableEnded) return;
    cancelled = true;
    void reader.cancel("client disconnected").catch(() => undefined);
  };
  res.once("close", onClose);

  try {
    while (!cancelled) {
      const { done, value } = await reader.read();
      if (done) break;
      if (res.destroyed) break;
      if (!res.write(value)) await waitForDrain(res);
    }
    if (!res.writableEnded) res.end();
  } catch (error) {
    if (!res.writableEnded) res.destroy(error instanceof Error ? error : undefined);
  } finally {
    res.off("close", onClose);
    void reader.cancel().catch(() => undefined);
  }
}
