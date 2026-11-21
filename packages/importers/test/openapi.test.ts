import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { GapError, silentLogger, type ActionContext, type AnyAction } from "gapmcp-core";
import {
  importOpenApi,
  parseOpenApiSpec,
  type OpenApiOperation,
} from "../src/index.js";

const fixturePath = fileURLToPath(new URL("./fixtures/customers.yaml", import.meta.url));

async function fixture(): Promise<string> {
  return readFile(fixturePath, "utf8");
}

function context(signal?: AbortSignal): ActionContext {
  return {
    principal: { id: "tester" },
    scopes: ["customers:write"],
    dryRun: false,
    signal: signal ?? new AbortController().signal,
    traceId: "trace_test",
    logger: silentLogger,
  };
}

function actionNamed(actions: AnyAction[], name: string): AnyAction {
  const action = actions.find((candidate) => candidate.name === name);
  if (!action) throw new Error(`Missing action ${name}`);
  return action;
}

interface FetchCall {
  url: string;
  init: RequestInit | undefined;
}

function mockFetch(
  respond: () => Response | Promise<Response>,
): { fetch: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    return respond();
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("parseOpenApiSpec", () => {
  it("parses YAML and resolves local refs with cycle protection", async () => {
    const spec = parseOpenApiSpec(await fixture());

    const customer = spec.components.schemas.Customer;
    expect(customer.properties.id.description).toBe("Customer id.");
    expect(customer.required).toEqual(["id", "name"]);
    expect(customer.properties.manager.type).toBe("object");
    expect(customer.properties.manager.properties.manager).toEqual({});

    const requestId = spec.paths["/customers"].get.parameters[1];
    expect(requestId.name).toBe("X-Request-Id");
    expect(requestId.schema.type).toBe("string");
  });

  it("accepts JSON text and plain objects without mutating the input", () => {
    const input = {
      openapi: "3.0.0",
      paths: { "/ping": { get: { responses: { "200": { description: "ok" } } } } },
    };
    const fromJson = parseOpenApiSpec(JSON.stringify(input));
    expect(fromJson.paths["/ping"].get.responses["200"].description).toBe("ok");

    const fromObject = parseOpenApiSpec(input);
    expect(fromObject).not.toBe(input);
    expect(fromObject).toEqual(input);
  });

  it("leaves external refs untouched instead of fetching them", () => {
    const spec = parseOpenApiSpec({
      openapi: "3.0.0",
      paths: {},
      components: { schemas: { External: { $ref: "other.yaml#/components/schemas/External" } } },
    });
    expect(spec.components.schemas.External).toEqual({
      $ref: "other.yaml#/components/schemas/External",
    });
  });

  it("rejects unparseable input with GapError INVALID_INPUT", () => {
    expect(() => parseOpenApiSpec("not: [valid")).toThrow(GapError);
  });
});

describe("importOpenApi", () => {
  it("imports operations, names them, and merges parameters and bodies", async () => {
    const actions = await importOpenApi({ spec: await fixture() });
    const names = actions.map((action) => action.name);

    expect(names).toContain("listCustomers");
    expect(names).toContain("createCustomer");
    expect(names).toContain("getCustomer");
    expect(names).toContain("deleteCustomer");
    expect(names).toContain("get.orders.order.id.items");
    expect(names).toContain("getCustomer.2");
    expect(names).toContain("ping");

    const list = actionNamed(actions, "listCustomers");
    expect(list.input).toMatchObject({
      type: "object",
      properties: {
        limit: { type: "integer", minimum: 1 },
        "X-Request-Id": { type: "string" },
      },
    });
    expect(list.tags).toEqual(["customers"]);
    expect(list.scopes).toEqual([]);
    expect(list.risk).toBe("low");

    const create = actionNamed(actions, "createCustomer");
    expect(create.input).toMatchObject({
      type: "object",
      required: ["name", "email"],
      properties: {
        name: { type: "string", description: "Customer display name." },
        email: { type: "string", description: "Contact email." },
        metadata: { type: "object", description: "Free-form metadata." },
      },
    });
    expect(create.ui).toMatchObject({ route: "/customers/new", action: "customers.create" });
    expect(create.output).toMatchObject({ type: "object" });

    const remove = actionNamed(actions, "deleteCustomer");
    expect(remove.risk).toBe("high");
    expect(remove.confirm).toBe(true);
    expect(remove.scopes).toEqual(["customers:write"]);
    expect(remove.input).toMatchObject({
      required: ["id", "X-Reason"],
      properties: { "X-Reason": { type: "string" } },
    });
  });

  it("uses operationId when present and a sanitized path otherwise", async () => {
    const actions = await importOpenApi({
      spec: {
        openapi: "3.0.0",
        paths: {
          "/customers/{id}": {
            get: { responses: { "200": { description: "ok" } } },
          },
          "/orders/{order-id}/items": {
            post: {
              operationId: "Create order item",
              responses: { "201": { description: "created" } },
            },
          },
        },
      },
    });

    expect(actions.map((action) => action.name)).toEqual([
      "get.customers.id",
      "Create.order.item",
    ]);
    expect(actions[0]?.description).toContain("HTTP GET /customers/{id}");
    expect(actions[0]?.description.length).toBeGreaterThanOrEqual(20);
  });

  it("filters with include and passes the resolved operation", async () => {
    const seen: OpenApiOperation[] = [];
    const actions = await importOpenApi({
      spec: await fixture(),
      include: (operation) => {
        seen.push(operation);
        return operation.method === "get" && operation.path.startsWith("/customers");
      },
    });

    expect(seen).toHaveLength(7);
    expect(seen[0]?.operation.summary).toBe("List customers");
    expect(actions.map((action) => action.name)).toEqual(["listCustomers", "getCustomer"]);
  });

  it("returns no actions when include rejects everything", async () => {
    const actions = await importOpenApi({ spec: await fixture(), include: () => false });
    expect(actions).toEqual([]);
  });

  it("executes GET requests with encoded paths, queries, and headers", async () => {
    const { fetch: fetchImpl, calls } = mockFetch(() => jsonResponse([]));
    const actions = await importOpenApi({ spec: await fixture(), fetch: fetchImpl });

    const list = actionNamed(actions, "listCustomers");
    const result = await list.execute(
      { limit: 5, "X-Request-Id": "req-1" },
      context(),
    );

    expect(result).toEqual([]);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://api.example.com/v1/customers?limit=5");
    expect(calls[0]?.init?.method).toBe("GET");
    expect(calls[0]?.init?.headers).toEqual({ "X-Request-Id": "req-1" });
    expect(calls[0]?.init?.body).toBeUndefined();

    const get = actionNamed(actions, "getCustomer");
    await get.execute({ id: "a/b" }, context());
    expect(calls[1]?.url).toBe("https://api.example.com/v1/customers/a%2Fb");
  });

  it("executes POST requests with a merged JSON body", async () => {
    const { fetch: fetchImpl, calls } = mockFetch(() => jsonResponse({ id: "c1" }, 201));
    const actions = await importOpenApi({ spec: await fixture(), fetch: fetchImpl });

    const create = actionNamed(actions, "createCustomer");
    const result = await create.execute(
      {
        name: "Ada",
        email: "ada@example.com",
        metadata: { plan: "pro" },
        ignored: "not-in-the-spec",
      },
      context(),
    );

    expect(result).toEqual({ id: "c1" });
    expect(calls[0]?.url).toBe("https://api.example.com/v1/customers");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(calls[0]?.init?.headers).toMatchObject({ "Content-Type": "application/json" });
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({
      name: "Ada",
      email: "ada@example.com",
      metadata: { plan: "pro" },
    });
  });

  it("executes DELETE with header parameters and the supplied baseUrl", async () => {
    const { fetch: fetchImpl, calls } = mockFetch(
      () => new Response(null, { status: 204 }),
    );
    const actions = await importOpenApi({
      spec: await fixture(),
      baseUrl: "https://mock.test/api/",
      fetch: fetchImpl,
    });

    const remove = actionNamed(actions, "deleteCustomer");
    const result = await remove.execute(
      { id: "42", "X-Reason": "duplicate" },
      context(),
    );

    expect(result).toBeUndefined();
    expect(calls[0]?.url).toBe("https://mock.test/api/customers/42");
    expect(calls[0]?.init?.method).toBe("DELETE");
    expect(calls[0]?.init?.headers).toEqual({ "X-Reason": "duplicate" });
  });

  it("supports Swagger 2.0 host, basePath, and body parameters", async () => {
    const { fetch: fetchImpl, calls } = mockFetch(() => jsonResponse({ id: "p1" }));
    const actions = await importOpenApi({
      spec: {
        swagger: "2.0",
        host: "api.example.com",
        basePath: "/v2",
        schemes: ["https"],
        paths: {
          "/pets/{id}": {
            post: {
              operationId: "updatePet",
              parameters: [
                { name: "id", in: "path", required: true, type: "string" },
                { name: "pet", in: "body", required: true, schema: { type: "object" } },
              ],
              responses: {
                "200": {
                  description: "ok",
                  schema: { type: "object", properties: { id: { type: "string" } } },
                },
              },
            },
          },
        },
      },
      fetch: fetchImpl,
    });

    const update = actionNamed(actions, "updatePet");
    expect(update.input).toMatchObject({
      required: ["id", "body"],
      properties: { body: { type: "object" } },
    });
    await update.execute({ id: 7, body: { name: "Rex" } }, context());
    expect(calls[0]?.url).toBe("https://api.example.com/v2/pets/7");
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({ name: "Rex" });
  });

  it.each([
    [401, "UNAUTHENTICATED"],
    [403, "FORBIDDEN"],
    [404, "NOT_FOUND"],
    [409, "CONFLICT"],
    [429, "RATE_LIMITED"],
    [400, "INVALID_INPUT"],
    [500, "UNAVAILABLE"],
  ])("maps upstream status %i to %s", async (status, code) => {
    const { fetch: fetchImpl } = mockFetch(
      () =>
        new Response('{"error":"upstream says no"}', {
          status,
          headers: { "content-type": "application/json" },
        }),
    );
    const actions = await importOpenApi({ spec: await fixture(), fetch: fetchImpl });
    const get = actionNamed(actions, "getCustomer");

    const error = await get.execute({ id: "1" }, context()).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(GapError);
    expect(error).toMatchObject({ code, status });
    expect((error as GapError).message).toContain("upstream says no");
  });

  it("caps error body snippets at 500 characters", async () => {
    const { fetch: fetchImpl } = mockFetch(
      () => new Response("x".repeat(1200), { status: 502 }),
    );
    const actions = await importOpenApi({ spec: await fixture(), fetch: fetchImpl });
    const ping = actionNamed(actions, "ping");

    const error = (await ping.execute({}, context()).catch((caught: unknown) => caught)) as GapError;
    expect(error.code).toBe("UNAVAILABLE");
    expect((error.details as { body: string }).body).toHaveLength(500);
  });

  it("passes an abort signal and reports aborts as timeouts", async () => {
    const controller = new AbortController();
    controller.abort();
    const fetchImpl = vi.fn(async () => {
      throw new DOMException("aborted", "AbortError");
    }) as unknown as typeof fetch;

    const actions = await importOpenApi({ spec: await fixture(), fetch: fetchImpl });
    const ping = actionNamed(actions, "ping");

    await expect(ping.execute({}, context(controller.signal))).rejects.toMatchObject({
      code: "TIMEOUT",
    });
  });
});
