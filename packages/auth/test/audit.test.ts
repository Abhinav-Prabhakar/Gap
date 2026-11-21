import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AuditEvent } from "gapmcp-core";
import { GapError } from "gapmcp-core";
import {
  JsonlAuditLog,
  MemoryAuditLog,
  createAuditEvent,
} from "../src/index";

function event(id: string): AuditEvent {
  return {
    id,
    timestamp: "2025-01-01T00:00:00.000Z",
    action: "invoices.read",
    principalId: "user_1",
    tenantId: "tenant_1",
    decision: "allowed",
    argsHash: "abc",
  };
}

describe("createAuditEvent", () => {
  it("fills generated fields and accepts explicit values", () => {
    const generated = createAuditEvent({
      action: "invoices.read",
      principalId: "user_1",
      decision: "allowed",
      timestamp: new Date("2025-02-03T04:05:06.000Z"),
    });
    expect(generated.id).toMatch(/^evt_/);
    expect(generated.timestamp).toBe("2025-02-03T04:05:06.000Z");

    const explicit = createAuditEvent({
      id: "evt_fixed",
      timestamp: 0,
      action: "invoices.read",
      principalId: "user_1",
      decision: "denied",
    });
    expect(explicit.id).toBe("evt_fixed");
    expect(explicit.timestamp).toBe("1970-01-01T00:00:00.000Z");
  });
});

describe("MemoryAuditLog", () => {
  it("records, lists, clears and bounds events", () => {
    const log = new MemoryAuditLog({ max: 2 });
    log.record(event("1"));
    log.record(event("2"));
    log.record(event("3"));

    expect(log.events.map((entry) => entry.id)).toEqual(["2", "3"]);
    expect(log.list()).toEqual(log.events);

    const snapshot = log.list();
    snapshot.pop();
    expect(log.events).toHaveLength(2);

    log.clear();
    expect(log.events).toHaveLength(0);
    expect(log.list()).toEqual([]);
  });

  it("supports an unbounded log and rejects invalid bounds", () => {
    const log = new MemoryAuditLog();
    for (let index = 0; index < 5; index += 1) {
      log.record(event(String(index)));
    }
    expect(log.list()).toHaveLength(5);

    expect(() => new MemoryAuditLog({ max: -1 })).toThrow(GapError);
    expect(() => new MemoryAuditLog({ max: 1.5 })).toThrow(GapError);
  });
});

describe("JsonlAuditLog", () => {
  let directory: string;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "gapmcp-auth-"));
  });

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("writes one JSON line per event and creates parent directories", async () => {
    const path = join(directory, "nested", "audit.jsonl");
    const log = new JsonlAuditLog(path);

    await log.record(event("1"));
    await log.record(event("2"));
    await log.close();

    const lines = (await readFile(path, "utf8")).trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]!)).toEqual(event("1"));
    expect(JSON.parse(lines[1]!)).toEqual(event("2"));
  });

  it("serializes concurrent writes in call order", async () => {
    const path = join(directory, "concurrent.jsonl");
    const log = new JsonlAuditLog(path);

    const writes = Array.from({ length: 25 }, (_value, index) =>
      log.record(event(String(index))),
    );
    await Promise.all(writes);
    await log.close();

    const lines = (await readFile(path, "utf8")).trimEnd().split("\n");
    expect(lines).toHaveLength(25);
    expect(
      lines.map((line) => (JSON.parse(line) as AuditEvent).id),
    ).toEqual(Array.from({ length: 25 }, (_value, index) => String(index)));
  });

  it("appends across instances and closes idempotently", async () => {
    const path = join(directory, "append.jsonl");
    const first = new JsonlAuditLog(path);
    await first.record(event("1"));
    await first.close();
    await first.close();

    const second = new JsonlAuditLog(path);
    await second.record(event("2"));
    await second.close();

    const lines = (await readFile(path, "utf8")).trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[1]!)).toEqual(event("2"));
  });

  it("rejects writes after close and empty paths", async () => {
    const log = new JsonlAuditLog(join(directory, "closed.jsonl"));
    await log.close();

    await expect(log.record(event("1"))).rejects.toBeInstanceOf(GapError);
    expect(() => new JsonlAuditLog("")).toThrow(GapError);
  });
});
