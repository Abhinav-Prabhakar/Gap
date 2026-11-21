export interface ReadinessSignal {
  id: string;
  label: string;
  weight: number;
  passed: boolean;
  detail: string;
  recommendation: string;
}

export interface ReadinessReport {
  url: string;
  score: number;
  grade: "A" | "B" | "C" | "D";
  signals: ReadinessSignal[];
}

export interface ScoreOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
}

async function probe(
  url: string,
  init: RequestInit,
  fetcher: typeof fetch,
  timeoutMs: number,
): Promise<{ ok: boolean; status: number; text: string; headers: Headers }> {
  try {
    const response = await fetcher(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    const text = await response.text();
    return { ok: response.ok, status: response.status, text, headers: response.headers };
  } catch {
    return { ok: false, status: 0, text: "", headers: new Headers() };
  }
}

function grade(score: number): ReadinessReport["grade"] {
  if (score >= 85) return "A";
  if (score >= 65) return "B";
  if (score >= 40) return "C";
  return "D";
}

/**
 * Scan a public app for the signals an agent needs: a native action surface,
 * discoverable auth, a health endpoint and semantic UI hooks. This is a
 * heuristic, not a security audit.
 */
export async function scoreAgentReadiness(
  input: string,
  options: ScoreOptions = {},
): Promise<ReadinessReport> {
  const base = new URL(input);
  base.pathname = base.pathname.replace(/\/$/, "");
  const root = base.origin + base.pathname.replace(/\/$/, "");
  const fetcher = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? 5000;

  const [openapi, swagger, mcp, metadata, health, home, llms] = await Promise.all([
    probe(`${root}/openapi.json`, { headers: { accept: "application/json" } }, fetcher, timeoutMs),
    probe(`${root}/swagger.json`, { headers: { accept: "application/json" } }, fetcher, timeoutMs),
    probe(
      `${root}/mcp`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "gap-score", version: "0.1.0" },
          },
        }),
      },
      fetcher,
      timeoutMs,
    ),
    probe(
      `${root}/.well-known/oauth-protected-resource`,
      { headers: { accept: "application/json" } },
      fetcher,
      timeoutMs,
    ),
    probe(`${root}/health`, { headers: { accept: "application/json" } }, fetcher, timeoutMs),
    probe(root + "/", { headers: { accept: "text/html" } }, fetcher, timeoutMs),
    probe(`${root}/llms.txt`, { headers: { accept: "text/plain" } }, fetcher, timeoutMs),
  ]);

  const specFound = openapi.ok || swagger.ok;
  const mcpFound =
    (mcp.status === 200 && /jsonrpc|result/i.test(mcp.text)) ||
    (mcp.status === 401 && mcp.headers.has("www-authenticate"));
  const metadataFound = metadata.ok && /authorization_servers|resource/i.test(metadata.text);
  const authChallenge = mcp.headers.get("www-authenticate") !== null || metadataFound;
  const domFound = home.ok && home.text.includes("data-gap-action");
  const healthFound = health.ok;
  const docsFound = llms.ok && llms.text.trim().length > 0;

  const signals: ReadinessSignal[] = [
    {
      id: "mcp",
      label: "MCP endpoint",
      weight: 35,
      passed: mcpFound,
      detail: mcpFound
        ? mcp.status === 401
          ? "Responds at /mcp with an auth challenge."
          : "Responds to MCP initialize at /mcp."
        : mcp.status
          ? `HTTP ${mcp.status} at /mcp.`
          : "No response at /mcp.",
      recommendation:
        "Mount a Gap (or any MCP) endpoint at /mcp with Streamable HTTP so agents can call typed actions.",
    },
    {
      id: "openapi",
      label: "OpenAPI spec",
      weight: 15,
      passed: specFound,
      detail: specFound ? "Found an OpenAPI document." : "No openapi.json or swagger.json.",
      recommendation:
        "Publish an OpenAPI document; `gap import openapi` can turn it into a reviewed action surface.",
    },
    {
      id: "metadata",
      label: "Protected-resource metadata",
      weight: 15,
      passed: metadataFound,
      detail: metadataFound
        ? "RFC 9728 metadata is discoverable."
        : "No /.well-known/oauth-protected-resource document.",
      recommendation:
        "Serve RFC 9728 metadata so agents can discover the authorization server and scopes.",
    },
    {
      id: "auth",
      label: "Auth signal",
      weight: 10,
      passed: authChallenge,
      detail: authChallenge
        ? "The endpoint advertises how to authenticate."
        : "No WWW-Authenticate challenge or metadata.",
      recommendation:
        "Return WWW-Authenticate: Bearer resource_metadata=... on 401 so agents can recover.",
    },
    {
      id: "dom",
      label: "Semantic DOM hooks",
      weight: 15,
      passed: domFound,
      detail: domFound
        ? "The homepage contains data-gap-action bindings."
        : "No data-gap-action attributes on the homepage.",
      recommendation:
        "Annotate key flows with data-gap-action so a browser agent can act on intent, not pixels.",
    },
    {
      id: "health",
      label: "Health endpoint",
      weight: 5,
      passed: healthFound,
      detail: healthFound ? "/health responds." : "No /health endpoint.",
      recommendation: "Expose an unauthenticated /health endpoint.",
    },
    {
      id: "docs",
      label: "Agent-readable docs",
      weight: 5,
      passed: docsFound,
      detail: docsFound ? "/llms.txt is present." : "No /llms.txt.",
      recommendation: "Publish /llms.txt describing your API and actions.",
    },
  ];

  const score = signals.reduce((total, signal) => total + (signal.passed ? signal.weight : 0), 0);
  return { url: root, score, grade: grade(score), signals };
}
