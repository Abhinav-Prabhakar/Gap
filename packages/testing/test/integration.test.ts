import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { ActionRegistry, defineAction, type AuthProvider } from "gapmcp-core";
import { callTool, listTools, startTestServer, type TestServer } from "../src/index";

const notes = new Map<string, string>();

const listNotes = defineAction({
  name: "notes.list",
  description: "List notes. Read-only and safe to call repeatedly.",
  input: z.object({}),
  output: z.object({ notes: z.array(z.string()) }),
  tags: ["read-only"],
  execute: () => ({ notes: [...notes.keys()] }),
});

const createNote = defineAction({
  name: "notes.create",
  description: "Create a note. Returns the new note id and does not notify anyone.",
  input: z.object({ title: z.string().describe("Note title.") }),
  output: z.object({ id: z.string(), title: z.string() }),
  scopes: ["notes:write"],
  execute: ({ title }) => {
    const id = `note_${notes.size + 1}`;
    notes.set(id, title);
    return { id, title };
  },
});

const auth: AuthProvider = {
  authenticate(request) {
    const header = request.headers.get("authorization");
    if (header === "Bearer write-key") {
      return { principal: { id: "usr_writer", type: "user", scopes: ["notes:read", "notes:write"] } };
    }
    if (header === "Bearer read-key") {
      return { principal: { id: "usr_reader", type: "user", scopes: ["notes:read"] } };
    }
    return null;
  },
  challenge: () => 'Bearer realm="gap"',
};

let handle: TestServer;

beforeAll(async () => {
  handle = await startTestServer({ registry: new ActionRegistry([listNotes, createNote]), auth });
});

afterAll(async () => {
  await handle.close();
});

describe("end-to-end MCP harness", () => {
  it("lists only tools visible to the principal", async () => {
    const tools = await listTools({ url: handle.url, token: "read-key" });
    const names = tools.map((tool) => tool.name);
    expect(names).toContain("notes.list");
    expect(names).not.toContain("notes.create");
    expect(names.filter((name) => !name.startsWith("gap."))).toEqual(["notes.list"]);
  });

  it("calls a tool and returns structured content", async () => {
    const result = await callTool({ url: handle.url, name: "notes.list", token: "read-key" });
    expect(result.isError).toBe(false);
    expect(result.structured).toEqual({ notes: [] });
  });

  it("returns a tool error for invalid input", async () => {
    const result = await callTool({ url: handle.url, name: "notes.create", args: { title: 4 }, token: "write-key" });
    expect(result.isError).toBe(true);
    expect(result.text).toMatch(/input/i);
  });

  it("rejects unauthenticated discovery", async () => {
    await expect(listTools({ url: handle.url })).rejects.toThrow(/401/);
  });
});
