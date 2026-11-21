import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  GapError,
  silentLogger,
  type ActionContext,
  type AnyAction,
} from "gapmcp-core";
import { scanNextRoutes } from "../src/index.js";

let root: string;
let emptyRoot: string;

const USERS_ROUTE = `// export async function DELETE() { return new Response(null); }
/* export const PUT = async () => new Response(null); */
export async function GET() {
  return Response.json([]);
}

export const POST = async () => {
  return Response.json({ ok: true });
};
`;

const USER_ROUTE = `export async function GET() {
  return Response.json({ id: "1" });
}

const PATCH = async () => Response.json({ ok: true });
export { PATCH };
`;

const REPORT_ROUTE = `export const DELETE = async () => new Response(null, { status: 204 });
`;

const DOCS_ROUTE = `export const GET = async () => Response.json({ docs: [] });
`;

const ORDERS_INDEX_ROUTE = `export async function PUT() {
  return Response.json({ ok: true });
}
`;

const ROOT_ROUTE = `export async function GET() {
  return Response.json({ home: true });
}
`;

async function writeRoute(relativePath: string, source: string): Promise<void> {
  const full = join(root, relativePath);
  await mkdir(join(full, ".."), { recursive: true });
  await writeFile(full, source, "utf8");
}

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "gap-next-"));
  emptyRoot = await mkdtemp(join(tmpdir(), "gap-next-empty-"));
  await writeRoute("app/api/users/route.ts", USERS_ROUTE);
  await writeRoute("app/api/users/[id]/route.ts", USER_ROUTE);
  await writeRoute("app/api/(admin)/reports/[reportId]/route.js", REPORT_ROUTE);
  await writeRoute("app/api/docs/[[...slug]]/route.ts", DOCS_ROUTE);
  await writeRoute("app/api/orders/index/route.ts", ORDERS_INDEX_ROUTE);
  await writeRoute("app/(marketing)/route.ts", ROOT_ROUTE);
  await writeFile(
    join(root, "app/api/users/page.tsx"),
    "export default function Page() {}",
    "utf8",
  );
});

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
  await rm(emptyRoot, { recursive: true, force: true });
});

function context(): ActionContext {
  return {
    principal: { id: "tester" },
    scopes: [],
    dryRun: false,
    signal: new AbortController().signal,
    traceId: "trace_next",
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

function mockFetch(respond: () => Response): {
  fetch: typeof fetch;
  calls: FetchCall[];
} {
  const calls: FetchCall[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    return respond();
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

describe("scanNextRoutes", () => {
  it("discovers exported methods, ignoring comment-only exports", async () => {
    const actions = await scanNextRoutes({ dir: root });
    const names = actions.map((action) => action.name).sort();

    expect(names).toEqual([
      "DELETE.api.reports.reportId",
      "GET.api.docs.slug",
      "GET.api.users",
      "GET.api.users.id",
      "GET.root",
      "PATCH.api.users.id",
      "POST.api.users",
      "PUT.api.orders",
    ]);
    expect(names).not.toContain("DELETE.api.users");
    expect(names).not.toContain("PUT.api.users");
    expect(names).not.toContain("PUT.api.orders.index");
  });

  it("mentions the source file and derives proxy input schemas", async () => {
    const actions = await scanNextRoutes({ dir: root });
    const get = actionNamed(actions, "GET.api.users.id");

    expect(get.description).toContain("app/api/users/[id]/route.ts");
    expect(get.input).toMatchObject({
      type: "object",
      required: ["id"],
      properties: {
        id: { type: "string" },
        query: { type: "object" },
      },
    });
    expect(get.input).not.toHaveProperty("properties.body");

    const post = actionNamed(actions, "POST.api.users");
    expect(post.input).toMatchObject({
      properties: { body: { type: "object" }, query: { type: "object" } },
    });

    const remove = actionNamed(actions, "DELETE.api.reports.reportId");
    expect(remove.risk).toBe("high");
    expect(remove.confirm).toBe(true);
  });

  it("proxies GET requests with route params and query values", async () => {
    const { fetch: fetchImpl, calls } = mockFetch(() =>
      Response.json({ id: "42" }),
    );
    const actions = await scanNextRoutes({
      dir: root,
      baseUrl: "https://proxy.test/",
      fetch: fetchImpl,
      headers: { "X-Proxy": "gap" },
    });

    const get = actionNamed(actions, "GET.api.users.id");
    const result = await get.execute(
      { id: "42", query: { expand: "team", tags: ["a", "b"] } },
      context(),
    );

    expect(result).toEqual({ id: "42" });
    expect(calls[0]?.url).toBe(
      "https://proxy.test/api/users/42?expand=team&tags=a&tags=b",
    );
    expect(calls[0]?.init?.method).toBe("GET");
    expect(calls[0]?.init?.headers).toEqual({ "X-Proxy": "gap" });
    expect(calls[0]?.init?.body).toBeUndefined();
  });

  it("proxies POST bodies and leftover query parameters", async () => {
    const { fetch: fetchImpl, calls } = mockFetch(() =>
      Response.json({ ok: true }),
    );
    const actions = await scanNextRoutes({
      dir: root,
      baseUrl: "https://proxy.test",
      fetch: fetchImpl,
    });

    const post = actionNamed(actions, "POST.api.users");
    await post.execute(
      { body: { name: "Ada" }, query: { notify: true } },
      context(),
    );

    expect(calls[0]?.url).toBe("https://proxy.test/api/users?notify=true");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(calls[0]?.init?.headers).toMatchObject({
      "Content-Type": "application/json",
    });
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({ name: "Ada" });
  });

  it("uses leftover arguments as the body for mutations without an explicit body", async () => {
    const { fetch: fetchImpl, calls } = mockFetch(() =>
      Response.json({ ok: true }),
    );
    const actions = await scanNextRoutes({
      dir: root,
      baseUrl: "https://proxy.test",
      fetch: fetchImpl,
    });

    const post = actionNamed(actions, "POST.api.users");
    await post.execute({ name: "Grace", role: "admin" }, context());

    expect(calls[0]?.url).toBe("https://proxy.test/api/users");
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({
      name: "Grace",
      role: "admin",
    });
  });

  it("proxies root and optional catch-all routes", async () => {
    const { fetch: fetchImpl, calls } = mockFetch(() => Response.json({}));
    const actions = await scanNextRoutes({
      dir: root,
      baseUrl: "https://proxy.test",
      fetch: fetchImpl,
    });

    await actionNamed(actions, "GET.root").execute({}, context());
    expect(calls[0]?.url).toBe("https://proxy.test/");

    await actionNamed(actions, "GET.api.docs.slug").execute(
      { slug: "guide" },
      context(),
    );
    expect(calls[1]?.url).toBe("https://proxy.test/api/docs/guide");

    await actionNamed(actions, "GET.api.docs.slug").execute({}, context());
    expect(calls[2]?.url).toBe("https://proxy.test/api/docs");
  });

  it("maps proxy failures to GapError by status", async () => {
    const { fetch: fetchImpl } = mockFetch(
      () => new Response('{"error":"no"}', { status: 404 }),
    );
    const actions = await scanNextRoutes({
      dir: root,
      baseUrl: "https://proxy.test",
      fetch: fetchImpl,
    });

    await expect(
      actionNamed(actions, "GET.api.users").execute({}, context()),
    ).rejects.toMatchObject({ code: "NOT_FOUND", status: 404 });
  });

  it("throws a clear wiring error when no baseUrl is supplied", async () => {
    const actions = await scanNextRoutes({ dir: root });
    const get = actionNamed(actions, "GET.api.users");

    const error = await get
      .execute({}, context())
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(GapError);
    expect(error).toMatchObject({ code: "UNAVAILABLE" });
    expect((error as GapError).message).toContain(
      "is not wired to an executor",
    );
    expect((error as GapError).message).toContain("app/api/users/route.ts");
  });

  it("returns an empty list for empty or missing directories", async () => {
    expect(await scanNextRoutes({ dir: emptyRoot })).toEqual([]);
    expect(await scanNextRoutes({ dir: join(emptyRoot, "missing") })).toEqual(
      [],
    );
  });

  it("works when dir is the app directory itself", async () => {
    const actions = await scanNextRoutes({ dir: join(root, "app") });
    expect(actions.map((action) => action.name)).toContain("GET.api.users");
    expect(actionNamed(actions, "GET.api.users").description).toContain(
      "api/users/route.ts",
    );
  });
});
