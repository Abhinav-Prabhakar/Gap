import { afterEach, describe, expect, it, vi } from "vitest";
import { createHandoffUrl, verifyHandoffState } from "../src/index.js";

const SECRET = "handoff-secret-value";

function tokenFrom(url: string): string {
  const token = new URL(url).searchParams.get("gap_state");
  if (!token) throw new Error("URL is missing gap_state");
  return token;
}

function decodePayload(token: string): Record<string, unknown> {
  const encoded = token.split(".")[1];
  if (!encoded) throw new Error("Token has no payload");
  return JSON.parse(
    Buffer.from(encoded, "base64url").toString("utf8"),
  ) as Record<string, unknown>;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("createHandoffUrl", () => {
  it("round-trips a signed token through a UI route", async () => {
    const url = await createHandoffUrl({
      baseUrl: "https://app.example.com/workspace",
      action: "invoices.create",
      args: { customerId: "cus_1", total: 42 },
      secret: SECRET,
      ttlMs: 60_000,
      path: "/invoices/new",
    });

    const parsed = new URL(url);
    expect(parsed.origin).toBe("https://app.example.com");
    expect(parsed.pathname).toBe("/invoices/new");
    expect([...parsed.searchParams.keys()]).toEqual(["gap_state"]);
    expect(url).not.toContain("cus_1");

    const token = tokenFrom(url);
    expect(token).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

    const state = await verifyHandoffState(token, SECRET);
    expect(state).not.toBeNull();
    expect(state?.action).toBe("invoices.create");
    expect(state?.args).toEqual({ customerId: "cus_1", total: 42 });
    expect(state!.exp - state!.iat).toBe(60_000);
    expect(state?.nonce).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("defaults to the root path and preserves existing query parameters", async () => {
    const rootUrl = await createHandoffUrl({
      baseUrl: "https://app.example.com",
      action: "docs.open",
      args: {},
      secret: SECRET,
      path: "/handoff?lang=en",
    });

    const parsed = new URL(rootUrl);
    expect(parsed.pathname).toBe("/handoff");
    expect(parsed.searchParams.get("lang")).toBe("en");
    expect(parsed.searchParams.get("gap_state")).toBeTruthy();

    const defaultPath = await createHandoffUrl({
      baseUrl: "https://app.example.com",
      action: "docs.open",
      args: {},
      secret: SECRET,
    });
    expect(new URL(defaultPath).pathname).toBe("/");
  });

  it("uses a fresh nonce for every URL", async () => {
    const options = {
      baseUrl: "https://app.example.com",
      action: "docs.open",
      args: {},
      secret: SECRET,
    } as const;
    const first = await createHandoffUrl(options);
    const second = await createHandoffUrl(options);

    const firstState = await verifyHandoffState(tokenFrom(first), SECRET);
    const secondState = await verifyHandoffState(tokenFrom(second), SECRET);
    expect(firstState?.nonce).not.toBe(secondState?.nonce);
  });

  it("rejects empty actions, secrets, and non-positive TTLs", async () => {
    await expect(
      createHandoffUrl({
        baseUrl: "https://app.example.com",
        action: "",
        args: {},
        secret: SECRET,
      }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(
      createHandoffUrl({
        baseUrl: "https://app.example.com",
        action: "a",
        args: {},
        secret: "",
      }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(
      createHandoffUrl({
        baseUrl: "https://app.example.com",
        action: "a",
        args: {},
        secret: SECRET,
        ttlMs: 0,
      }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });
});

describe("verifyHandoffState", () => {
  it("rejects a tampered payload", async () => {
    const token = tokenFrom(
      await createHandoffUrl({
        baseUrl: "https://app.example.com",
        action: "invoices.create",
        args: { total: 10 },
        secret: SECRET,
        path: "/invoices/new",
      }),
    );
    const parts = token.split(".");
    const payload = decodePayload(token);
    const tampered = Buffer.from(
      JSON.stringify({ ...payload, args: { total: 1_000_000 } }),
    ).toString("base64url");
    const forged = `v1.${tampered}.${parts[2]}`;

    expect(await verifyHandoffState(forged, SECRET)).toBeNull();
  });

  it("rejects the wrong secret", async () => {
    const token = tokenFrom(
      await createHandoffUrl({
        baseUrl: "https://app.example.com",
        action: "invoices.create",
        args: {},
        secret: SECRET,
      }),
    );
    expect(await verifyHandoffState(token, "another-secret")).toBeNull();
    expect(await verifyHandoffState(token, "")).toBeNull();
  });

  it("rejects an expired token", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

    const token = tokenFrom(
      await createHandoffUrl({
        baseUrl: "https://app.example.com",
        action: "invoices.create",
        args: {},
        secret: SECRET,
        ttlMs: 1_000,
      }),
    );
    expect(await verifyHandoffState(token, SECRET)).not.toBeNull();

    vi.advanceTimersByTime(1_500);
    expect(await verifyHandoffState(token, SECRET)).toBeNull();
  });

  it.each([
    "",
    "v1",
    "v1.only-two",
    "v2.eyJhIjoxfQ.signature",
    "v1.!!!.???",
    "v1.eyJhIjoxfQ.signature.extra",
  ])("returns null for malformed token %j", async (token) => {
    expect(await verifyHandoffState(token, SECRET)).toBeNull();
  });

  it("returns null for payloads with invalid fields", async () => {
    const secret = SECRET;
    const payload = Buffer.from(
      JSON.stringify({ action: "", args: {}, iat: 1, exp: 2, nonce: "n" }),
    ).toString("base64url");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = Buffer.from(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)),
    ).toString("base64url");

    expect(
      await verifyHandoffState(`v1.${payload}.${signature}`, secret),
    ).toBeNull();
  });
});
