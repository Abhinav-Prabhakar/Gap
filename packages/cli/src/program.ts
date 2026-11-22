import { readFileSync, writeFileSync, existsSync, mkdirSync, copyFileSync } from "node:fs";
import { createServer } from "node:http";
import path from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { ActionRegistry } from "gapmcp-core";
import { createGapServer, createStdioServer, MemoryApprovalStore } from "gapmcp-server";
import { apiKeyAuth, MemoryAuditLog } from "gapmcp-auth";
import { GapPolicy, parsePolicy } from "gapmcp-policy";
import { MemoryTracer } from "gapmcp-observability";
import { lintRegistry, MockPlanner, httpPlanner, runEvals, type EvalCase, type Planner } from "gapmcp-evals";
import { importOpenApi } from "gapmcp-importers";
import { buildDomManifest, renderDomRuntime } from "gapmcp-dom";
import { loadRegistry } from "./load";
import { startInspector } from "./inspector";
import packageJson from "../package.json";
import { scoreAgentReadiness } from "./score";

function packageVersion(): string {
  return packageJson.version ?? "0.0.0";
}

function writeIfAllowed(file: string, content: string, force: boolean): boolean {
  if (existsSync(file) && !force) {
    console.log(pc.yellow(`skip ${file} (exists; use --force to overwrite)`));
    return false;
  }
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content);
  console.log(pc.green(`created ${file}`));
  return true;
}

const ACTIONS_TEMPLATE = `import { defineAction } from "gapmcp-core";
import { z } from "zod";

/**
 * Actions are the one contract every agent surface compiles from.
 * Replace this in-memory store with your real application services.
 */
const notes = new Map<string, { id: string; title: string; body: string; createdAt: string }>();

const noteSchema = z.object({
  id: z.string().describe("Note id, e.g. note_8f2."),
  title: z.string().describe("Short note title."),
  body: z.string().describe("Note body as plain text."),
  createdAt: z.string().describe("ISO-8601 creation timestamp."),
});

export const listNotes = defineAction({
  name: "notes.list",
  description: "List notes, newest first. Read-only and safe to call repeatedly.",
  input: z.object({
    limit: z.number().int().min(1).max(100).default(20).describe("Maximum notes to return."),
  }),
  output: z.object({ notes: z.array(noteSchema), total: z.number() }),
  tags: ["read-only"],
  execute: async ({ limit }) => {
    const all = [...notes.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return { notes: all.slice(0, limit), total: all.length };
  },
});

export const createNote = defineAction({
  name: "notes.create",
  description: "Create a note. Returns the new note; does not notify anyone.",
  input: z.object({
    title: z.string().min(1).max(200).describe("Short note title."),
    body: z.string().max(20_000).describe("Note body as plain text."),
  }),
  output: noteSchema,
  scopes: ["notes:write"],
  risk: "low",
  idempotent: false,
  execute: async ({ title, body }, ctx) => {
    const id = "note_" + Math.random().toString(36).slice(2, 10);
    const note = { id, title, body, createdAt: new Date().toISOString() };
    notes.set(id, note);
    ctx.logger.info("note created", { id, actor: ctx.principal.id });
    return note;
  },
});

export const actions = [listNotes, createNote];
export default actions;
`;

const SERVER_TEMPLATE = `import { createServer } from "node:http";
import { createRegistry } from "gapmcp-core";
import { createGapServer } from "gapmcp-server";
import { actions } from "./gap.actions";

const registry = createRegistry(...actions);
const token = process.env.GAP_TOKEN;

const gap = createGapServer({
  registry,
  name: "my-gap-app",
  version: "0.1.0",
  baseUrl: process.env.GAP_BASE_URL ?? "http://127.0.0.1:4400",
  ...(token
    ? { auth: (await import("gapmcp-auth")).apiKeyAuth({ keys: [{ key: token, principal: { id: "local", type: "user", scopes: ["*"] } }] }) }
    : {}),
});

const port = Number(process.env.PORT ?? 4400);
createServer((req, res) => void gap.handleNode(req, res)).listen(port, "127.0.0.1", () => {
  console.error("Gap MCP endpoint: http://127.0.0.1:" + port + "/mcp");
  if (!token) console.error("No GAP_TOKEN set: anonymous access with all scopes (development only).");
});
`;

const POLICY_TEMPLATE = `{
  "version": 1,
  "default": "allow",
  "rules": [
    { "tools": ["notes.create"], "confirm": true },
    { "tools": ["*.delete", "*.refund"], "deny": true, "reason": "Destructive tools are disabled in this demo." }
  ]
}
`;

const ENV_TEMPLATE = `# Bearer token accepted by the demo server. Change before exposing it.
GAP_TOKEN=dev-token-change-me
GAP_BASE_URL=http://127.0.0.1:4400
`;

const PACKAGE_TEMPLATE = `{
  "name": "my-gap-app",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "tsx gap.server.ts",
    "inspect": "gap inspect gap.actions.ts"
  },
  "dependencies": {
    "gapmcp-auth": "^0.1.0",
    "gapmcp-core": "^0.1.0",
    "gapmcp-server": "^0.1.0",
    "zod": "^4.0.0"
  },
  "devDependencies": {
    "tsx": "^4.20.0",
    "typescript": "^5.9.0"
  }
}
`;

export function buildProgram(): Command {
  const program = new Command("gap")
    .description("Gap — typed actions for agents. One contract for MCP, OpenAPI and UI automation.")
    .version(packageVersion(), "-v, --version", "print the CLI version")
    .showHelpAfterError();

  program
    .command("init")
    .argument("[dir]", "directory to scaffold", ".")
    .option("-f, --force", "overwrite existing files", false)
    .description("scaffold actions, a server and a policy file")
    .action(async (dir: string, options: { force: boolean }) => {
      const root = path.resolve(dir);
      mkdirSync(root, { recursive: true });
      writeIfAllowed(path.join(root, "gap.actions.ts"), ACTIONS_TEMPLATE, options.force);
      writeIfAllowed(path.join(root, "gap.server.ts"), SERVER_TEMPLATE, options.force);
      writeIfAllowed(path.join(root, "gap.policy.json"), POLICY_TEMPLATE, options.force);
      writeIfAllowed(path.join(root, ".env.example"), ENV_TEMPLATE, options.force);
      const packageFile = path.join(root, "package.json");
      if (!existsSync(packageFile)) writeIfAllowed(packageFile, PACKAGE_TEMPLATE, options.force);
      console.log("");
      console.log(pc.bold("Next:"));
      console.log("  npm install");
      console.log("  npx gap inspect gap.actions.ts");
      console.log("  npx gap serve gap.actions.ts");
    });

  program
    .command("import")
    .command("openapi")
    .argument("<spec>", "OpenAPI JSON or YAML file")
    .option("-o, --out <file>", "generated actions file", "gap.openapi.ts")
    .option("-b, --base-url <url>", "upstream API base URL")
    .option("--dry-run", "print imported tool names without writing files", false)
    .description("import an OpenAPI spec as typed actions")
    .action(async (specPath: string, options: { out: string; baseUrl?: string; dryRun: boolean }) => {
      const absoluteSpec = path.resolve(specPath);
      if (!existsSync(absoluteSpec)) throw new Error(`Spec not found: ${specPath}`);
      const spec = readFileSync(absoluteSpec, "utf8");
      const actions = await importOpenApi({ spec, baseUrl: options.baseUrl, include: () => true });
      if (options.dryRun) {
        for (const action of actions) console.log(action.name);
        console.log(pc.dim(`${actions.length} tools, dry run, nothing written.`));
        return;
      }
      const out = path.resolve(options.out);
      const outDir = path.dirname(out);
      mkdirSync(outDir, { recursive: true });
      const copied = path.join(outDir, path.basename(absoluteSpec));
      if (path.resolve(copied) !== absoluteSpec) copyFileSync(absoluteSpec, copied);
      const relative = "./" + path.basename(copied);
      const base = options.baseUrl ? JSON.stringify(options.baseUrl) : "undefined";
      const source = `// Generated by gap import openapi. Review descriptions and risk levels.
import { readFileSync } from "node:fs";
import { importOpenApi } from "gapmcp-importers";

const spec = readFileSync(new URL(${JSON.stringify(relative)}, import.meta.url), "utf8");

export const actions = await importOpenApi({ spec, baseUrl: ${base} });
export default actions;
`;
      writeFileSync(out, source);
      console.log(pc.green(`created ${options.out} with ${actions.length} tools`));
      for (const action of actions) console.log("  " + pc.cyan(action.name));
    });

  program
    .command("lint")
    .argument("<registry>", "actions module")
    .option("--json", "machine-readable output", false)
    .option("--strict", "treat warnings as failures", false)
    .description("lint tool names, descriptions, scopes and risk")
    .action(async (registryPath: string, options: { json: boolean; strict: boolean }) => {
      const registry = await loadRegistry(registryPath);
      const report = lintRegistry(registry);
      if (options.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log(pc.bold(`Gap lint · ${registry.size} actions · score ${report.score}/100`));
        if (report.issues.length === 0 && report.ambiguous.length === 0) {
          console.log(pc.green("No issues."));
        }
        for (const issue of report.issues) {
          const level = issue.level === "error" ? pc.red("error") : pc.yellow("warn ");
          console.log(`${level} ${pc.dim(issue.code)} ${issue.action ? pc.cyan(issue.action) + " " : ""}${issue.message}`);
        }
        for (const [a, b] of report.ambiguous) {
          console.log(`${pc.yellow("warn ")} ${pc.dim("ambiguous")} ${pc.cyan(a)} and ${pc.cyan(b)} have very similar descriptions.`);
        }
      }
      const failed = report.issues.some((issue) => issue.level === "error") || (options.strict && report.issues.length > 0);
      if (failed) process.exitCode = 1;
    });

  program
    .command("evals")
    .argument("<cases>", "JSON file with eval cases")
    .requiredOption("-r, --registry <file>", "actions module")
    .option("-p, --planner <kind>", "mock | http", "http")
    .option("--endpoint <url>", "OpenAI-compatible base URL", "https://api.openai.com/v1")
    .option("-m, --model <name>", "model for the http planner", "gpt-4.1-mini")
    .option("--scopes <list>", "comma-separated principal scopes", "*")
    .option("--json", "machine-readable output", false)
    .description("measure whether an agent picks the right tool")
    .action(async (casesPath: string, options: { registry: string; planner: string; endpoint: string; model: string; scopes: string; json: boolean }) => {
      const registry = await loadRegistry(options.registry);
      const parsed = JSON.parse(readFileSync(path.resolve(casesPath), "utf8")) as EvalCase[] | { cases: EvalCase[] };
      const cases = Array.isArray(parsed) ? parsed : parsed.cases;
      if (!Array.isArray(cases) || cases.length === 0) throw new Error("No eval cases found.");

      let planner: Planner;
      if (options.planner === "mock") {
        planner = new MockPlanner(cases.map((item) => ({ tool: item.expectedTool, args: item.expectedArgs })));
      } else if (options.planner === "http") {
        planner = httpPlanner({ endpoint: options.endpoint, model: options.model, apiKey: process.env.OPENAI_API_KEY });
      } else {
        throw new Error(`Unknown planner "${options.planner}". Use mock or http.`);
      }

      const report = await runEvals({
        registry,
        cases,
        planner,
        scopes: options.scopes.split(",").map((scope) => scope.trim()).filter(Boolean),
      });
      if (options.json) console.log(report.toJSON());
      else {
        console.log(report.summary());
        console.log("");
        console.log(pc.bold(`Pass rate: ${Math.round(report.passRate * 100)}% (${report.passed}/${report.total})`));
      }
      if (report.passed < report.total) process.exitCode = 1;
    });

  program
    .command("inspect")
    .argument("<registry>", "actions module")
    .option("-p, --port <port>", "inspector port", "4400")
    .option("-h, --host <host>", "bind host", "127.0.0.1")
    .option("--token <token>", "bearer token for the MCP endpoint")
    .option("--policy <file>", "policy JSON file")
    .description("open the local inspector and playground")
    .action(async (registryPath: string, options: { port: string; host: string; token?: string; policy?: string }) => {
      const registry = await loadRegistry(registryPath);
      const policy = options.policy ? new GapPolicy(parsePolicy(readFileSync(path.resolve(options.policy), "utf8"))) : undefined;
      const approvals = new MemoryApprovalStore();
      const auth = options.token
        ? apiKeyAuth({ keys: [{ key: options.token, principal: { id: "inspector", type: "user", scopes: ["*"] } }] })
        : undefined;
      const handle = await startInspector({
        registry,
        port: Number(options.port),
        host: options.host,
        token: options.token,
        approvals,
        server: {
          ...(auth ? { auth } : {}),
          ...(policy ? { policy } : {}),
          approvalStore: approvals,
          audit: new MemoryAuditLog(),
          tracer: new MemoryTracer(),
          baseUrl: `http://${options.host}:${options.port}`,
        },
      });
      console.log(pc.bold("Gap Inspector"));
      console.log(`  UI:   ${pc.cyan(handle.url)}`);
      console.log(`  MCP:  ${pc.cyan(handle.url + "/mcp")}`);
      console.log(pc.dim("  Ctrl-C to stop."));
    });

  program
    .command("serve")
    .argument("<registry>", "actions module")
    .option("-p, --port <port>", "HTTP port", "4400")
    .option("-h, --host <host>", "bind host", "0.0.0.0")
    .option("--stdio", "serve MCP over stdio instead of HTTP", false)
    .option("--token <token>", "bearer token required by the endpoint")
    .option("--policy <file>", "policy JSON file")
    .option("--base-url <url>", "public base URL used in links")
    .option("--handoff-secret <secret>", "enable signed human-handoff links")
    .option("--stateless", "no server-side MCP sessions (serverless friendly)", false)
    .description("serve a registry as an MCP endpoint")
    .action(async (registryPath: string, options: Record<string, string | boolean>) => {
      const registry = await loadRegistry(registryPath);
      const policy = options.policy
        ? new GapPolicy(parsePolicy(readFileSync(path.resolve(String(options.policy)), "utf8")))
        : undefined;
      const token = typeof options.token === "string" ? options.token : process.env.GAP_TOKEN;
      const auth = token
        ? apiKeyAuth({ keys: [{ key: token, principal: { id: "cli", type: "user", scopes: ["*"] } }] })
        : undefined;
      const baseUrl = String(options.baseUrl ?? `http://127.0.0.1:${options.port}`);
      const common = {
        registry,
        name: path.basename(registryPath),
        baseUrl,
        ...(auth ? { auth } : {}),
        ...(policy ? { policy } : {}),
        ...(options.handoffSecret ? { handoffSecret: String(options.handoffSecret) } : {}),
        audit: new MemoryAuditLog(),
        tracer: new MemoryTracer(),
      };

      if (options.stdio) {
        const handle = await createStdioServer(common);
        console.error("Gap MCP server listening on stdio.");
        const close = async () => {
          await handle.close();
          process.exit(0);
        };
        process.on("SIGINT", () => void close());
        process.on("SIGTERM", () => void close());
        return;
      }

      const gap = createGapServer({ ...common, sessionMode: options.stateless ? "stateless" : "stateful" });
      const http = createServer((req, res) => void gap.handleNode(req, res));
      const port = Number(options.port);
      await new Promise<void>((resolve) => http.listen(port, String(options.host), () => resolve()));
      console.log(pc.bold("Gap MCP server"));
      console.log(`  endpoint: ${pc.cyan(baseUrl + "/mcp")}`);
      console.log(`  metadata: ${pc.cyan(baseUrl + "/.well-known/oauth-protected-resource")}`);
      console.log(pc.dim(`  ${registry.size} tools · ${auth ? "bearer auth" : "anonymous (dev)"}`));
      const close = async () => {
        http.close();
        await gap.close();
        process.exit(0);
      };
      process.on("SIGINT", () => void close());
      process.on("SIGTERM", () => void close());
    });

  program
    .command("dom")
    .argument("<registry>", "actions module")
    .option("-o, --out <file>", "manifest output", "gap.dom.json")
    .option("--runtime <file>", "write the browser runtime as a standalone JS file")
    .description("compile actions into semantic DOM bindings and a browser runtime")
    .action(async (registryPath: string, options: { out: string; runtime?: string }) => {
      const registry = await loadRegistry(registryPath);
      const manifest = buildDomManifest(registry);
      writeFileSync(path.resolve(options.out), JSON.stringify(manifest, null, 2) + "\n");
      console.log(pc.green(`created ${options.out} with ${manifest.actions.length} bindings`));
      if (options.runtime) {
        writeFileSync(path.resolve(options.runtime), renderDomRuntime() + "\n");
        console.log(pc.green(`created ${options.runtime}`));
      }
    });

  program
    .command("doctor")
    .argument("[registry]", "optional actions module to check")
    .description("check the local environment and an optional registry")
    .action(async (registryPath?: string) => {
      const major = Number(process.versions.node.split(".")[0]);
      console.log(`node       ${process.versions.node} ${major >= 20 ? pc.green("ok") : pc.red("requires >= 20")}`);
      console.log(`platform   ${process.platform} ${process.arch}`);
      console.log(`cwd        ${process.cwd()}`);
      console.log(`gap        ${packageVersion()}`);
      if (registryPath) {
        try {
          const registry = await loadRegistry(registryPath);
          const report = lintRegistry(registry);
          console.log(`registry   ${registry.size} tools, score ${report.score}/100`);
          if (report.issues.some((issue) => issue.level === "error")) process.exitCode = 1;
        } catch (error) {
          console.log(`registry   ${pc.red((error as Error).message)}`);
          process.exitCode = 1;
        }
      } else {
        console.log(pc.dim("Pass a registry path to validate it: gap doctor gap.actions.ts"));
      }
    });

  program
    .command("score")
    .argument("<url>", "public app URL to scan")
    .option("--json", "print the full report as JSON", false)
    .description("score an app's agent readiness: MCP, auth metadata, DOM hooks and docs")
    .action(async (url: string, options: { json: boolean }) => {
      const report = await scoreAgentReadiness(url);
      if (options.json) {
        console.log(JSON.stringify(report, null, 2));
        return;
      }
      console.log(`${pc.bold(report.url)}  score ${report.score}/100  grade ${report.grade}`);
      for (const signal of report.signals) {
        console.log(
          `${signal.passed ? pc.green("pass") : pc.yellow("miss")}  ${signal.label.padEnd(26)} ${pc.dim(signal.detail)}`,
        );
        if (!signal.passed) console.log(pc.dim(`      ${signal.recommendation}`));
      }
    });

  program
    .command("tools")
    .argument("<registry>", "actions module")
    .description("list every action as an MCP tool")
    .action(async (registryPath: string) => {
      const registry = await loadRegistry(registryPath);
      for (const tool of registry.toToolDescriptors()) {
        const action = registry.get(tool.name);
        console.log(`${pc.cyan(tool.name)}  ${pc.dim(`${action?.risk ?? "low"} risk, ${(action?.scopes ?? []).join(", ") || "no scopes"}`)}`);
        console.log(`  ${tool.description}`);
      }
    });

  return program;
}

export async function main(argv = process.argv): Promise<void> {
  await buildProgram().parseAsync(argv);
}
