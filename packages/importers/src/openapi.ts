import {
  GapError,
  invalidInput,
  type AnyAction,
  type RiskLevel,
} from "gapmcp-core";
import { parse as parseYaml } from "yaml";
import {
  appendQueryValue,
  describeMethod,
  isRecord,
  joinUrl,
  pickJsonMediaType,
  readUpstreamBody,
  riskForMethod,
  signalFrom,
  upstreamError,
  type ImportedHttpMethod,
} from "./http.js";

/** One path + method pair discovered in an OpenAPI document. */
export interface OpenApiOperation {
  /** Lowercase HTTP method, e.g. `get`. */
  method: ImportedHttpMethod;
  /** The templated path exactly as written in the document. */
  path: string;
  /** The resolved operation object (local `$ref`s already expanded). */
  operation: Record<string, any>;
}

/** Options accepted by {@link importOpenApi}. */
export interface ImportOpenApiOptions {
  /** A JSON string, YAML string, or already-parsed OpenAPI document. */
  spec: string | object;
  /** Overrides the first `servers` URL (or Swagger 2.0 host). */
  baseUrl?: string;
  /** Return false to skip an operation. Receives the resolved operation. */
  include?: (operation: OpenApiOperation) => boolean;
  /** Injectable fetch, used by tests and custom transports. */
  fetch?: typeof fetch;
  /** Headers merged into every upstream request. */
  headers?: Record<string, string>;
}

/** Methods imported from an OpenAPI path item, in stable output order. */
const METHODS: readonly ImportedHttpMethod[] = [
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "head",
  "options",
];

interface ParameterInfo {
  name: string;
  location: "path" | "query" | "header";
  required: boolean;
  schema: Record<string, any>;
  description: string;
}

interface BodyInfo {
  schema: Record<string, any>;
  required: boolean;
  description: string;
  /** Top-level property names when the body object is flattened into input. */
  propertyNames: string[];
  /** True when body properties are exposed at the input root. */
  merged: boolean;
}

interface ExecuteConfig {
  baseUrl: string;
  method: ImportedHttpMethod;
  path: string;
  parameters: ParameterInfo[];
  body?: BodyInfo;
  headers: Record<string, string>;
  fetch?: typeof fetch;
}

function decodePointerSegment(segment: string): string {
  let decoded = segment.replace(/~1/g, "/").replace(/~0/g, "~");
  try {
    decoded = decodeURIComponent(decoded);
  } catch {
    // Keep the raw segment when it is not valid percent-encoding.
  }
  return decoded;
}

function lookupPointer(root: unknown, pointer: string): unknown {
  if (pointer === "#" || pointer === "#/") return root;
  if (!pointer.startsWith("#/")) return undefined;
  let current: unknown = root;
  for (const raw of pointer.slice(2).split("/")) {
    const key = decodePointerSegment(raw);
    if (Array.isArray(current)) {
      const index = Number(key);
      if (!Number.isInteger(index) || index < 0 || index >= current.length)
        return undefined;
      current = current[index];
    } else if (isRecord(current)) {
      if (!(key in current)) return undefined;
      current = current[key];
    } else {
      return undefined;
    }
  }
  return current;
}

/**
 * Resolve local JSON-pointer `$ref`s recursively. External references are
 * intentionally left untouched so importing never performs network I/O.
 * A repeated reference on the same branch becomes `{}` to break cycles.
 */
function resolveRefs(
  value: unknown,
  root: unknown,
  stack: ReadonlySet<string>,
): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => resolveRefs(item, root, stack));
  }
  if (!isRecord(value)) return value;

  const ref = value.$ref;
  if (typeof ref === "string") {
    if (!ref.startsWith("#")) return { ...value };
    if (stack.has(ref)) return {};
    const target = lookupPointer(root, ref);
    if (target === undefined) {
      const { $ref: _ignored, ...siblings } = value;
      return resolveRefs(siblings, root, stack);
    }
    const nextStack = new Set(stack);
    nextStack.add(ref);
    const resolved = resolveRefs(target, root, nextStack);
    const { $ref: _ignored, ...siblings } = value;
    if (Object.keys(siblings).length === 0) return resolved;
    if (isRecord(resolved)) {
      return {
        ...resolved,
        ...(resolveRefs(siblings, root, stack) as Record<string, unknown>),
      };
    }
    return resolveRefs(siblings, root, stack);
  }

  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    result[key] = resolveRefs(item, root, stack);
  }
  return result;
}

function expandServerVariables(url: string, variables: unknown): string {
  if (!isRecord(variables)) return url;
  return url.replace(/\{([^{}]+)\}/g, (match, name: string) => {
    const variable = variables[name];
    if (isRecord(variable) && typeof variable.default === "string")
      return variable.default;
    return match;
  });
}

function serverUrl(spec: Record<string, any>): string {
  if (Array.isArray(spec.servers) && spec.servers.length > 0) {
    const first = spec.servers[0];
    if (
      isRecord(first) &&
      typeof first.url === "string" &&
      first.url.length > 0
    ) {
      return expandServerVariables(first.url, first.variables);
    }
  }
  if (
    typeof spec.swagger === "string" &&
    typeof spec.host === "string" &&
    spec.host.length > 0
  ) {
    const scheme =
      Array.isArray(spec.schemes) && typeof spec.schemes[0] === "string"
        ? spec.schemes[0]
        : "https";
    const basePath = typeof spec.basePath === "string" ? spec.basePath : "";
    return `${scheme}://${spec.host}${basePath}`;
  }
  return "";
}

/**
 * Parse an OpenAPI 3.x or Swagger 2.0 document from JSON, YAML, or an object,
 * then expand every local `$ref`. The returned document is a new object; the
 * caller's object is never mutated.
 */
export function parseOpenApiSpec(input: string | object): Record<string, any> {
  let parsed: unknown;
  if (typeof input === "string") {
    const text = input.trim();
    if (text.length === 0) {
      throw invalidInput("An OpenAPI document cannot be empty.");
    }
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      try {
        parsed = parseYaml(text) as unknown;
      } catch (error) {
        throw new GapError(
          "Failed to parse the OpenAPI document as JSON or YAML.",
          {
            code: "INVALID_INPUT",
            cause: error,
          },
        );
      }
    }
  } else {
    parsed = input;
  }

  if (!isRecord(parsed)) {
    throw invalidInput("The OpenAPI document must be a JSON/YAML object.");
  }
  return resolveRefs(parsed, parsed, new Set()) as Record<string, any>;
}

function parameterSchema(parameter: Record<string, any>): Record<string, any> {
  if (isRecord(parameter.schema)) return { ...parameter.schema };
  const schema: Record<string, any> = {};
  for (const key of [
    "type",
    "format",
    "items",
    "enum",
    "default",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
  ]) {
    if (parameter[key] !== undefined) schema[key] = parameter[key];
  }
  return schema;
}

function mergeParameters(
  pathItem: Record<string, any>,
  operation: Record<string, any>,
): Record<string, any>[] {
  const merged = new Map<string, Record<string, any>>();
  const add = (value: unknown): void => {
    if (!isRecord(value)) return;
    const name = typeof value.name === "string" ? value.name : "";
    const location = typeof value.in === "string" ? value.in : "";
    if (!name || !location) return;
    merged.set(`${location}:${name}`, value);
  };
  if (Array.isArray(pathItem.parameters))
    for (const value of pathItem.parameters) add(value);
  if (Array.isArray(operation.parameters))
    for (const value of operation.parameters) add(value);
  return [...merged.values()];
}

function buildParameters(raw: Record<string, any>[]): ParameterInfo[] {
  const parameters: ParameterInfo[] = [];
  for (const parameter of raw) {
    const location = parameter.in;
    if (location !== "path" && location !== "query" && location !== "header")
      continue;
    const name = parameter.name;
    if (typeof name !== "string" || name.length === 0) continue;
    const schema = parameterSchema(parameter);
    const fallback = `${location === "path" ? "Path" : location === "query" ? "Query" : "Header"} parameter "${name}".`;
    const description =
      typeof parameter.description === "string" &&
      parameter.description.trim().length > 0
        ? parameter.description.trim()
        : typeof schema.description === "string" &&
            schema.description.trim().length > 0
          ? schema.description.trim()
          : fallback;
    parameters.push({
      name,
      location,
      required: location === "path" || parameter.required === true,
      schema,
      description,
    });
  }
  return parameters;
}

function bodyFromOperation(
  operation: Record<string, any>,
  rawParameters: Record<string, any>[],
): BodyInfo | undefined {
  if (isRecord(operation.requestBody)) {
    const requestBody = operation.requestBody;
    const mediaType = pickJsonMediaType(requestBody.content);
    if (mediaType && isRecord(mediaType.schema)) {
      const schema = mediaType.schema;
      const description =
        typeof requestBody.description === "string" &&
        requestBody.description.trim().length > 0
          ? requestBody.description.trim()
          : typeof schema.description === "string" &&
              schema.description.trim().length > 0
            ? schema.description.trim()
            : "JSON request body.";
      return describeBody(schema, requestBody.required === true, description);
    }
  }

  // Swagger 2.0 represents the body as an `in: body` parameter.
  for (const parameter of rawParameters) {
    if (parameter.in !== "body") continue;
    const schema = isRecord(parameter.schema)
      ? parameter.schema
      : { type: "object" };
    const description =
      typeof parameter.description === "string" &&
      parameter.description.trim().length > 0
        ? parameter.description.trim()
        : typeof schema.description === "string" &&
            schema.description.trim().length > 0
          ? schema.description.trim()
          : "JSON request body.";
    return describeBody(schema, parameter.required === true, description);
  }
  return undefined;
}

function describeBody(
  schema: Record<string, any>,
  required: boolean,
  description: string,
): BodyInfo {
  const properties = isRecord(schema.properties)
    ? schema.properties
    : undefined;
  const merged =
    properties !== undefined &&
    (schema.type === "object" || schema.type === undefined) &&
    Object.keys(properties).length > 0;
  return {
    schema,
    required,
    description,
    merged,
    propertyNames: merged ? Object.keys(properties) : [],
  };
}

function describeProperty(
  schema: Record<string, any>,
  description: string,
): Record<string, any> {
  const property = { ...schema };
  if (
    typeof property.description !== "string" ||
    property.description.trim().length === 0
  ) {
    property.description = description;
  }
  return property;
}

function buildInputSchema(
  parameters: ParameterInfo[],
  body: BodyInfo | undefined,
): Record<string, any> {
  const properties: Record<string, any> = {};
  const required = new Set<string>();

  for (const parameter of parameters) {
    properties[parameter.name] = describeProperty(
      parameter.schema,
      parameter.description,
    );
    if (parameter.required) required.add(parameter.name);
  }

  if (body?.merged) {
    const bodyProperties = isRecord(body.schema.properties)
      ? body.schema.properties
      : {};
    for (const name of body.propertyNames) {
      if (name in properties) continue;
      const schema = isRecord(bodyProperties[name]) ? bodyProperties[name] : {};
      properties[name] = describeProperty(
        schema,
        `Request body field "${name}".`,
      );
    }
    if (body.required && Array.isArray(body.schema.required)) {
      for (const name of body.schema.required) {
        if (typeof name === "string" && name in properties) required.add(name);
      }
    }
  } else if (body) {
    properties.body = describeProperty(body.schema, body.description);
    if (body.required) required.add("body");
  }

  const schema: Record<string, any> = { type: "object", properties };
  if (required.size > 0) schema.required = [...required];
  return schema;
}

function outputSchema(
  operation: Record<string, any>,
): Record<string, any> | undefined {
  const responses = operation.responses;
  if (!isRecord(responses)) return undefined;
  for (const [status, response] of Object.entries(responses)) {
    if (!/^2(?:\d\d|xx)$/i.test(status) || !isRecord(response)) continue;
    const mediaType = pickJsonMediaType(response.content);
    if (mediaType && isRecord(mediaType.schema)) return mediaType.schema;
    if (isRecord(response.schema)) return response.schema;
  }
  return undefined;
}

function sanitizeOperationId(value: string): string {
  return value
    .trim()
    .replace(/[^A-Za-z0-9_.-]+/g, ".")
    .replace(/\.{2,}/g, ".")
    .replace(/^[.\-]+|[.\-]+$/g, "");
}

function pathToActionName(path: string): string {
  const segments = path
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) =>
      segment
        .replace(/[{}]/g, "")
        .replace(/[^A-Za-z0-9]+/g, ".")
        .replace(/^[.]+|[.]+$/g, "")
        .toLowerCase(),
    )
    .filter((segment) => segment.length > 0);
  return segments.length > 0 ? segments.join(".") : "root";
}

function baseActionName(
  method: ImportedHttpMethod,
  path: string,
  operation: Record<string, any>,
): string {
  const operationId =
    typeof operation.operationId === "string"
      ? sanitizeOperationId(operation.operationId)
      : "";
  const candidate =
    operationId.length > 0
      ? operationId
      : `${method}.${pathToActionName(path)}`;
  const prefixed = /^[A-Za-z]/.test(candidate)
    ? candidate
    : `action.${candidate}`;
  const collapsed = prefixed.replace(/\.{2,}/g, ".").replace(/[.\-]+$/g, "");
  return collapsed.length > 0 ? collapsed.slice(0, 120) : `${method}.root`;
}

function uniqueName(base: string, used: Set<string>): string {
  if (!used.has(base)) {
    used.add(base);
    return base;
  }
  let counter = 2;
  while (used.has(`${base}.${counter}`)) counter += 1;
  const name = `${base}.${counter}`;
  used.add(name);
  return name;
}

function operationDescription(
  operation: Record<string, any>,
  method: ImportedHttpMethod,
  path: string,
): string {
  const summary =
    typeof operation.summary === "string" ? operation.summary.trim() : "";
  const description =
    typeof operation.description === "string"
      ? operation.description.trim()
      : "";
  const note = `HTTP ${describeMethod(method)} ${path}.`;
  const composed = [summary, description, note]
    .filter((part) => part.length > 0)
    .join(" ");
  if (composed.length >= 20) return composed;
  return `Call ${describeMethod(method)} ${path} on the upstream API.`;
}

function extensionScopes(operation: Record<string, any>): string[] {
  const scopes = operation["x-gap-scopes"];
  if (!Array.isArray(scopes)) return [];
  return scopes.filter((scope): scope is string => typeof scope === "string");
}

function extensionUi(
  operation: Record<string, any>,
): Record<string, any> | undefined {
  const ui = operation["x-gap-ui"];
  return isRecord(ui) ? ui : undefined;
}

function setHeader(
  headers: Record<string, string>,
  name: string,
  value: string,
): void {
  const existing = Object.keys(headers).find(
    (key) => key.toLowerCase() === name.toLowerCase(),
  );
  headers[existing ?? name] = value;
}

function buildUrl(config: ExecuteConfig, args: Record<string, any>): string {
  const replaced = config.path.replace(
    /\{([^{}]+)\}/g,
    (_match, rawName: string) => {
      const name = rawName.trim();
      const value = args[name];
      if (value === undefined || value === null) {
        throw invalidInput(`Missing required path parameter "${name}".`);
      }
      return encodeURIComponent(String(value));
    },
  );
  const base = joinUrl(config.baseUrl, replaced);
  const query = new URLSearchParams();
  for (const parameter of config.parameters) {
    if (parameter.location !== "query") continue;
    appendQueryValue(query, parameter.name, args[parameter.name]);
  }
  const serialized = query.toString();
  if (serialized.length === 0) return base;
  return `${base}${base.includes("?") ? "&" : "?"}${serialized}`;
}

function bodyValue(config: ExecuteConfig, args: Record<string, any>): unknown {
  const body = config.body;
  if (!body) return undefined;
  if (body.merged) {
    const value: Record<string, unknown> = {};
    for (const name of body.propertyNames) {
      if (args[name] !== undefined) value[name] = args[name];
    }
    if (Object.keys(value).length > 0) return value;
  }
  return args.body;
}

function createExecutor(config: ExecuteConfig): AnyAction["execute"] {
  return async (rawInput: unknown, ctx) => {
    const args = isRecord(rawInput) ? rawInput : {};
    const url = buildUrl(config, args);
    const headers: Record<string, string> = { ...config.headers };

    for (const parameter of config.parameters) {
      if (parameter.location !== "header") continue;
      const value = args[parameter.name];
      if (value !== undefined && value !== null)
        setHeader(headers, parameter.name, String(value));
    }

    const payload = bodyValue(config, args);
    const method = describeMethod(config.method);
    const init: RequestInit = {
      method,
      headers,
      ...(signalFrom(ctx) ? { signal: signalFrom(ctx) } : {}),
    };
    if (
      payload !== undefined &&
      config.method !== "get" &&
      config.method !== "head"
    ) {
      init.body = JSON.stringify(payload);
      setHeader(headers, "Content-Type", "application/json");
    }

    const fetcher = config.fetch ?? globalThis.fetch;
    if (typeof fetcher !== "function") {
      throw new GapError(
        "No fetch implementation is available for this imported action.",
        {
          code: "UNAVAILABLE",
        },
      );
    }

    let response: Response;
    try {
      response = await fetcher(url, init);
    } catch (error) {
      if (signalFrom(ctx)?.aborted) {
        throw new GapError(`Request ${method} ${config.path} was aborted.`, {
          code: "TIMEOUT",
          cause: error,
        });
      }
      throw new GapError(
        `Request ${method} ${config.path} failed before a response was received.`,
        {
          code: "UNAVAILABLE",
          cause: error,
        },
      );
    }

    const text = await response.text();
    if (!response.ok) {
      throw upstreamError(response.status, response.statusText, text);
    }
    return readUpstreamBody(text, response.headers.get("content-type"));
  };
}

/**
 * Import every supported operation from an OpenAPI document as Gap actions.
 * Tool names come from `operationId`, or `<method>.<sanitized path>`.
 */
export async function importOpenApi(
  options: ImportOpenApiOptions,
): Promise<AnyAction[]> {
  const spec = parseOpenApiSpec(options.spec);
  const baseUrl = options.baseUrl ?? serverUrl(spec);
  const paths = isRecord(spec.paths) ? spec.paths : {};
  const used = new Set<string>();
  const actions: AnyAction[] = [];

  for (const [path, rawPathItem] of Object.entries(paths)) {
    if (!isRecord(rawPathItem)) continue;
    for (const method of METHODS) {
      const operation = rawPathItem[method];
      if (!isRecord(operation)) continue;

      if (options.include && !options.include({ method, path, operation }))
        continue;

      const rawParameters = mergeParameters(rawPathItem, operation);
      const parameters = buildParameters(rawParameters);
      const body = bodyFromOperation(operation, rawParameters);
      const name = uniqueName(baseActionName(method, path, operation), used);
      const risk = riskForMethod(method);
      const summary =
        typeof operation.summary === "string" ? operation.summary.trim() : "";
      const tags = Array.isArray(operation.tags)
        ? operation.tags.filter((tag): tag is string => typeof tag === "string")
        : [];
      const ui = extensionUi(operation);
      const output = outputSchema(operation);

      const action: AnyAction = {
        name,
        description: operationDescription(operation, method, path),
        input: buildInputSchema(parameters, body),
        ...(output ? { output } : {}),
        scopes: extensionScopes(operation),
        risk: risk.risk,
        ...(risk.confirm ? { confirm: true } : {}),
        ...(tags.length > 0 ? { tags } : {}),
        ...(ui ? { ui } : {}),
        ...(summary.length > 0 ? { title: summary } : {}),
        meta: {
          "gap/openapi": { method, path },
        },
        execute: createExecutor({
          baseUrl,
          method,
          path,
          parameters,
          ...(body ? { body } : {}),
          headers: { ...(options.headers ?? {}) },
          ...(options.fetch ? { fetch: options.fetch } : {}),
        }),
      };
      actions.push(action);
    }
  }

  return actions;
}

/** Exposed for downstream tools that need the risk policy without executing. */
export function importedRisk(method: ImportedHttpMethod): {
  risk: RiskLevel;
  confirm?: true;
} {
  return riskForMethod(method);
}
