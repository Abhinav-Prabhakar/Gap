import type { IncomingMessage, ServerResponse } from "node:http";
import type { GapServer } from "./server.js";
import { createGapServer } from "./server.js";
import type { GapServerOptions } from "./types.js";

/**
 * A web-standard handler returned by {@link createFetchHandler}. It is callable
 * as `handler(request)` so it can be re-exported directly as a Next.js
 * `GET`/`POST`/`DELETE` route handler, and it exposes the underlying server for
 * negotiation, inspection and shutdown.
 */
export interface GapFetchHandler {
  (request: Request): Promise<Response>;
  fetch(request: Request): Promise<Response>;
  readonly server: GapServer;
  close(): Promise<void>;
}

/** Create a standalone MCP server and return a web `Request` handler. */
export function createFetchHandler(options: GapServerOptions): GapFetchHandler {
  const server = createGapServer(options);
  const handler = ((request: Request) => server.fetch(request)) as GapFetchHandler;
  Object.defineProperties(handler, {
    fetch: { value: (request: Request) => server.fetch(request), enumerable: true },
    server: { value: server, enumerable: true },
    close: { value: () => server.close(), enumerable: true },
  });
  return handler;
}

/**
 * A Node request listener returned by {@link createNodeHandler}. Pass it to
 * `http.createServer`, `https.createServer` or a framework that accepts a Node
 * listener.
 */
export interface GapNodeHandler {
  (req: IncomingMessage, res: ServerResponse): Promise<void>;
  readonly server: GapServer;
  close(): Promise<void>;
}

/** Create a standalone MCP server and return a Node request listener. */
export function createNodeHandler(options: GapServerOptions): GapNodeHandler {
  const server = createGapServer(options);
  const handler = ((req: IncomingMessage, res: ServerResponse) =>
    server.handleNode(req, res)) as GapNodeHandler;
  Object.defineProperties(handler, {
    server: { value: server, enumerable: true },
    close: { value: () => server.close(), enumerable: true },
  });
  return handler;
}
