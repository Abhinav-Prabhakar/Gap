import { readdir, readFile, stat } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { GapError, invalidInput, type AnyAction, type ActionDefinition } from "gapmcp-core";
import {
  appendQueryValue,
  isRecord,
  joinUrl,
  readUpstreamBody,
  riskForMethod,
  signalFrom,
  upstreamError,
} from "./http.js";

/** The Next.js App Router HTTP method exports this scanner understands. */
export type NextRouteMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

/** Options accepted by {@link scanNextRoutes}. */
export interface ScanNextRoutesOptions {
  /** Project root (containing `app/`), the app directory itself, or an empty path. */
  dir: string;
  /** When set, imported actions proxy to this origin instead of throwing. */
  baseUrl?: string;
  /** Injectable fetch, used by tests and custom transports. */
  fetch?: typeof fetch;
  /** Headers merged into every proxied request. */
  headers?: Record<string, string>;
}

const METHOD_NAMES: readonly NextRouteMethod[] = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
];

const IGNORED_DIRECTORIES = new Set(["node_modules", ".next", ".git", ".turbo", "dist"]);

interface RouteFile {
  absolute: string;
  /** POSIX-style path relative to the project root, used in descriptions. */
  label: string;
  routePath: string;
}

/**
 * Remove `//` and `/* *\/` comments while preserving string literals and line
 * breaks, so a commented-out handler is not mistaken for a real export.
 */
function stripComments(source: string): string {
  let output = "";
  let index = 0;
  let quote: string | null = null;
  let lineComment = false;
  let blockComment = false;

  while (index < source.length) {
    const char = source[index]!;
    const next = source[index + 1];

    if (lineComment) {
      if (char === "\n") {
        lineComment = false;
        output += char;
      } else {
        output += " ";
      }
      index += 1;
      continue;
    }

    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        output += "  ";
        index += 2;
        continue;
      }
      output += char === "\n" ? "\n" : " ";
      index += 1;
      continue;
    }

    if (quote !== null) {
      output += char;
      if (char === "\\" && next !== undefined) {
        output += next;
        index += 2;
        continue;
      }
      if (char === quote) quote = null;
      index += 1;
      continue;
    }

    if (char === "/" && next === "/") {
      lineComment = true;
      output += "  ";
      index += 2;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      output += "  ";
      index += 2;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      output += char;
      index += 1;
      continue;
    }

    output += char;
    index += 1;
  }

  return output;
}

function detectMethods(source: string): NextRouteMethod[] {
  const code = stripComments(source);
  const found = new Set<NextRouteMethod>();

  for (const method of METHOD_NAMES) {
    const declaration = new RegExp(
      String.raw`\bexport\s+(?:async\s+)?function\s+${method}\b`,
    );
    const assignment = new RegExp(
      String.raw`\bexport\s+(?:const|let|var)\s+${method}\b`,
    );
    if (declaration.test(code) || assignment.test(code)) found.add(method);
  }

  const exportLists = /\bexport\s*\{([^}]*)\}/g;
  for (const match of code.matchAll(exportLists)) {
    const body = match[1] ?? "";
    for (const part of body.split(",")) {
      const exported = part.trim().split(/\s+as\s+/i)[0]?.trim();
      if (exported && (METHOD_NAMES as readonly string[]).includes(exported)) {
        found.add(exported as NextRouteMethod);
      }
    }
  }

  return METHOD_NAMES.filter((method) => found.has(method));
}

function transformSegment(segment: string): string | null {
  if (segment.startsWith("(") && segment.endsWith(")")) return null;
  if (segment.toLowerCase() === "index") return null;

  const optionalCatchAll = /^\[\[\.\.\.(.+)\]\]$/.exec(segment);
  if (optionalCatchAll) return `:${optionalCatchAll[1]}?`;
  const catchAll = /^\[\.\.\.(.+)\]$/.exec(segment);
  if (catchAll) return `:${catchAll[1]}`;
  const dynamic = /^\[(.+)\]$/.exec(segment);
  if (dynamic) return `:${dynamic[1]}`;
  return segment;
}

function routePathForFile(appRoot: string, file: string): string {
  const directory = dirname(file);
  const segments = relative(appRoot, directory)
    .split(sep)
    .filter((segment) => segment.length > 0)
    .map(transformSegment)
    .filter((segment): segment is string => segment !== null);
  return `/${segments.join("/")}`.replace(/\/{2,}/g, "/");
}

function actionName(method: NextRouteMethod, routePath: string): string {
  const segments = routePath
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) =>
      segment
        .replace(/^:/, "")
        .replace(/\?$/, "")
        .replace(/[^A-Za-z0-9]+/g, ".")
        .replace(/^[.]+|[.]+$/g, "")
        .toLowerCase(),
    )
    .filter((segment) => segment.length > 0);
  return `${method}.${segments.length > 0 ? segments.join(".") : "root"}`;
}

function pathParameterNames(routePath: string): string[] {
  const names: string[] = [];
  for (const match of routePath.matchAll(/:([A-Za-z0-9_]+)\??/g)) {
    const name = match[1];
    if (name && !names.includes(name)) names.push(name);
  }
  return names;
}

function nextInputSchema(routePath: string, method: NextRouteMethod): Record<string, any> {
  const properties: Record<string, any> = {};
  for (const name of pathParameterNames(routePath)) {
    properties[name] = {
      type: "string",
      description: `Path parameter "${name}" for ${method} ${routePath}.`,
    };
  }
  properties.query = {
    type: "object",
    additionalProperties: true,
    properties: {},
    description: `Query parameters forwarded to ${method} ${routePath}.`,
  };
  if (method !== "GET" && method !== "HEAD") {
    properties.body = {
      type: "object",
      additionalProperties: true,
      properties: {},
      description: `JSON request body forwarded to ${method} ${routePath}.`,
    };
  }
  const schema: Record<string, any> = {
    type: "object",
    properties,
    additionalProperties: true,
  };
  const required = pathParameterNames(routePath);
  if (required.length > 0) schema.required = required;
  return schema;
}

interface ProxyConfig {
  baseUrl: string;
  routePath: string;
  method: NextRouteMethod;
  headers: Record<string, string>;
  fetch?: typeof fetch;
}

function setHeader(headers: Record<string, string>, name: string, value: string): void {
  const existing = Object.keys(headers).find((key) => key.toLowerCase() === name.toLowerCase());
  headers[existing ?? name] = value;
}

function resolveRoutePath(config: ProxyConfig, args: Record<string, any>): string {
  const nested = isRecord(args.params) ? args.params : undefined;
  let resolved = config.routePath.replace(
    /:([A-Za-z0-9_]+)(\?)?/g,
    (_match, name: string, optional: string | undefined) => {
      const value = args[name] ?? nested?.[name];
      if (value === undefined || value === null || value === "") {
        if (optional) return "";
        throw invalidInput(`Missing required route parameter "${name}".`);
      }
      return encodeURIComponent(String(value));
    },
  );
  resolved = resolved.replace(/\/{2,}/g, "/");
  if (!resolved.startsWith("/")) resolved = `/${resolved}`;
  return resolved;
}

function createProxyExecutor(config: ProxyConfig): ActionDefinition["execute"] {
  return async (rawInput: unknown, ctx) => {
    const args = isRecord(rawInput) ? rawInput : {};
    const routePath = resolveRoutePath(config, args);
    let url = joinUrl(config.baseUrl, routePath);

    const query = new URLSearchParams();
    if (isRecord(args.query)) {
      for (const [name, value] of Object.entries(args.query)) appendQueryValue(query, name, value);
    }

    const consumed = new Set([
      ...pathParameterNames(config.routePath),
      "params",
      "query",
      "body",
      "headers",
    ]);
    const leftovers: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(args)) {
      if (!consumed.has(name) && value !== undefined) leftovers[name] = value;
    }

    const hasBody = config.method !== "GET" && config.method !== "HEAD";
    const fallbackBody = hasBody && args.body === undefined ? leftovers : undefined;
    if (hasBody && fallbackBody === undefined) {
      for (const [name, value] of Object.entries(leftovers)) appendQueryValue(query, name, value);
    }

    const serialized = query.toString();
    if (serialized.length > 0) url += `${url.includes("?") ? "&" : "?"}${serialized}`;

    const headers: Record<string, string> = { ...config.headers };
    if (isRecord(args.headers)) {
      for (const [name, value] of Object.entries(args.headers)) {
        if (typeof value === "string") setHeader(headers, name, value);
      }
    }

    const init: RequestInit = {
      method: config.method,
      headers,
      ...(signalFrom(ctx) ? { signal: signalFrom(ctx) } : {}),
    };

    const payload = hasBody ? (args.body ?? fallbackBody) : undefined;
    if (payload !== undefined) {
      init.body = JSON.stringify(payload);
      setHeader(headers, "Content-Type", "application/json");
    }

    const fetcher = config.fetch ?? globalThis.fetch;
    if (typeof fetcher !== "function") {
      throw new GapError("No fetch implementation is available for this imported route.", {
        code: "UNAVAILABLE",
      });
    }

    let response: Response;
    try {
      response = await fetcher(url, init);
    } catch (error) {
      if (signalFrom(ctx)?.aborted) {
        throw new GapError(`Request ${config.method} ${routePath} was aborted.`, {
          code: "TIMEOUT",
          cause: error,
        });
      }
      throw new GapError(`Request ${config.method} ${routePath} failed before a response was received.`, {
        code: "UNAVAILABLE",
        cause: error,
      });
    }

    const text = await response.text();
    if (!response.ok) {
      throw upstreamError(response.status, response.statusText, text);
    }
    return readUpstreamBody(text, response.headers.get("content-type"));
  };
}

function unwiredExecutor(file: string): ActionDefinition["execute"] {
  return async () => {
    throw new GapError(
      `Route imported from ${file} is not wired to an executor. Pass baseUrl or replace execute.`,
      { code: "UNAVAILABLE" },
    );
  };
}

async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

async function resolveRoots(dir: string): Promise<{ appRoot: string; projectRoot: string }> {
  const absolute = resolve(dir);
  const direct = join(absolute, "app");
  if (await isDirectory(direct)) return { appRoot: direct, projectRoot: absolute };

  const srcApp = join(absolute, "src", "app");
  if (await isDirectory(srcApp)) return { appRoot: srcApp, projectRoot: join(absolute, "src") };

  return { appRoot: absolute, projectRoot: absolute };
}

async function collectRouteFiles(directory: string, files: string[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return;
    throw error;
  }

  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    if (IGNORED_DIRECTORIES.has(entry.name)) continue;
    const full = join(directory, entry.name);
    if (entry.isDirectory()) {
      await collectRouteFiles(full, files);
    } else if (entry.isFile() && /^route\.(?:ts|js)$/.test(entry.name)) {
      files.push(full);
    }
  }
}

/**
 * Scan a Next.js App Router tree (`app/**\/route.ts|js`) and turn each exported
 * HTTP method into an action. With `baseUrl`, actions proxy to it; without one
 * they are still discoverable but throw a clear wiring error when called.
 */
export async function scanNextRoutes(options: ScanNextRoutesOptions): Promise<AnyAction[]> {
  const { appRoot, projectRoot } = await resolveRoots(options.dir);
  const absoluteFiles: string[] = [];
  await collectRouteFiles(appRoot, absoluteFiles);

  const actions: AnyAction[] = [];
  const used = new Set<string>();

  for (const absolute of absoluteFiles) {
    const label = relative(projectRoot, absolute).split(sep).join("/");
    const routePath = routePathForFile(appRoot, absolute);
    let source: string;
    try {
      source = await readFile(absolute, "utf8");
    } catch (error) {
      throw new GapError(`Failed to read route file ${label}.`, {
        code: "INTERNAL",
        cause: error,
        expose: false,
      });
    }

    for (const method of detectMethods(source)) {
      const base = actionName(method, routePath);
      let name = base;
      let counter = 2;
      while (used.has(name)) {
        name = `${base}.${counter}`;
        counter += 1;
      }
      used.add(name);

      const description = `Handle ${method} ${routePath} requests from ${label}. Imported from a Next.js App Router route handler.`;
      const risk = riskForMethod(method.toLowerCase() as
        | "get"
        | "post"
        | "put"
        | "patch"
        | "delete"
        | "head"
        | "options");
      const execute =
        options.baseUrl !== undefined && options.baseUrl.length > 0
          ? createProxyExecutor({
              baseUrl: options.baseUrl,
              routePath,
              method,
              headers: { ...(options.headers ?? {}) },
              ...(options.fetch ? { fetch: options.fetch } : {}),
            })
          : unwiredExecutor(label);

      actions.push({
        name,
        description,
        input: nextInputSchema(routePath, method),
        scopes: [],
        risk,
        ...(risk.confirm ? { confirm: true } : {}),
        tags: ["next"],
        meta: { "gap/next": { file: label, path: routePath } },
        execute,
      });
    }
  }

  return actions.sort((a, b) => a.name.localeCompare(b.name));
}

/** The route path a Next.js directory would serve, exposed for CLI display. */
export function nextRoutePath(appRoot: string, routeFile: string): string {
  return routePathForFile(resolve(appRoot), resolve(routeFile));
}

/** The source label used in descriptions for a route file. */
export function nextRouteLabel(projectRoot: string, routeFile: string): string {
  return relative(resolve(projectRoot), resolve(routeFile)).split(sep).join("/");
}
