import { describe, expect, it } from "vitest";
import { GapError } from "gapmcp-core";
import { HmacApprovalGate } from "../src/index";

const ACTION = "invoices.delete";
const PRINCIPAL = "user_1";
const ARGS = { id: "inv_1", nested: { b: 2, a: 1 } };
const REQUEST = { action: ACTION, args: ARGS, principalId: PRINCIPAL };
const NOW = 1_700_000_000_000;

function decodePayload(token: string): Record<string, unknown> {
  const segment = token.split(".")[1];
  if (!segment) throw new Error("Token has no payload.");
  return JSON.parse(
    Buffer.from(segment, "base64url").toString("utf8"),
  ) as Record<string, unknown>;
}

function encodePayload(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

describe("HmacApprovalGate", () => {
  it("issues and verifies a grant bound to args, action and principal", async () => {
    const gate = new HmacApprovalGate({ secret: "test-secret", now: () => NOW });
    const issued = await gate.issue({ ...REQUEST, ttlMs: 60_000 });

    expect(issued.token).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const payload = decodePayload(issued.token);
    expect(payload.principalId).toBe(PRINCIPAL);
    expect(payload.approvedBy).toBe(PRINCIPAL);
    expect(payload.action).toBe(ACTION);
    expect(payload.iat).toBe(NOW);
    expect(payload.exp).toBe(NOW + 60_000);
    expect(typeof payload.nonce).toBe("string");

    const grant = await gate.verify(issued.token, REQUEST);
    expect(grant).toEqual(issued.grant);
    expect(grant).toEqual({
      id: issued.grant.id,
      action: ACTION,
      argsHash: issued.grant.argsHash,
      approvedBy: PRINCIPAL,
      issuedAt: NOW,
      expiresAt: NOW + 60_000,
    });
  });

  it("hashes arguments canonically regardless of key order", async () => {
    const gate = new HmacApprovalGate({ secret: "test-secret", now: () => NOW });
    const issued = await gate.issue({
      action: ACTION,
      args: { b: 2, a: 1 },
      principalId: PRINCIPAL,
    });

    const grant = await gate.verify(issued.token, {
      action: ACTION,
      args: { a: 1, b: 2 },
      principalId: PRINCIPAL,
    });
    expect(grant).not.toBeNull();
  });

  it("uses the default ten minute lifetime", async () => {
    const gate = new HmacApprovalGate({ secret: "test-secret", now: () => NOW });
    const issued = await gate.issue(REQUEST);
    const payload = decodePayload(issued.token);

    expect((payload.exp as number) - (payload.iat as number)).toBe(10 * 60 * 1000);
    expect(issued.grant.expiresAt - issued.grant.issuedAt).toBe(10 * 60 * 1000);
  });

  it("rejects different arguments, actions or principals", async () => {
    const gate = new HmacApprovalGate({ secret: "test-secret", now: () => NOW });
    const issued = await gate.issue(REQUEST);

    expect(
      await gate.verify(issued.token, { ...REQUEST, args: { id: "inv_2" } }),
    ).toBeNull();
    expect(
      await gate.verify(issued.token, { ...REQUEST, action: "invoices.refund" }),
    ).toBeNull();
    expect(
      await gate.verify(issued.token, { ...REQUEST, principalId: "user_2" }),
    ).toBeNull();
  });

  it("rejects tokens with a tampered signature or payload", async () => {
    const gate = new HmacApprovalGate({ secret: "test-secret", now: () => NOW });
    const issued = await gate.issue(REQUEST);

    const last = issued.token.slice(-1);
    const tamperedSignature =
      issued.token.slice(0, -1) + (last === "A" ? "B" : "A");
    expect(await gate.verify(tamperedSignature, REQUEST)).toBeNull();

    const [version, payload, signature] = issued.token.split(".");
    expect(version).toBe("v1");
    expect(payload).toBeDefined();
    expect(signature).toBeDefined();
    const changed = decodePayload(issued.token);
    changed.action = "invoices.refund";
    const tamperedPayload = `v1.${encodePayload(changed)}.${signature}`;
    expect(await gate.verify(tamperedPayload, REQUEST)).toBeNull();
  });

  it("rejects tokens signed with a different secret", async () => {
    const issuer = new HmacApprovalGate({
      secret: "first-secret",
      now: () => NOW,
    });
    const verifier = new HmacApprovalGate({
      secret: "second-secret",
      now: () => NOW,
    });

    const issued = await issuer.issue(REQUEST);
    expect(await verifier.verify(issued.token, REQUEST)).toBeNull();
  });

  it("rejects expired grants, including exactly at expiry", async () => {
    let now = 1_000_000;
    const gate = new HmacApprovalGate({
      secret: "test-secret",
      ttlMs: 1_000,
      now: () => now,
    });
    const issued = await gate.issue(REQUEST);

    expect(await gate.verify(issued.token, REQUEST)).not.toBeNull();
    now += 999;
    expect(await gate.verify(issued.token, REQUEST)).not.toBeNull();
    now += 1;
    expect(await gate.verify(issued.token, REQUEST)).toBeNull();
  });

  it("rejects malformed tokens before parsing JSON", async () => {
    const gate = new HmacApprovalGate({ secret: "test-secret", now: () => NOW });
    const signature = "A".repeat(43);
    const malformed = [
      "",
      "v1",
      "v1.payload",
      "v2.abc.def",
      "v1.@@@.@@@",
      `v1.${encodePayload("not an object")}.${signature}`,
      `v1.${encodePayload({})}.${signature}`,
      `v1.${encodePayload({ id: "a" })}.${signature}`,
      `v1.${"a".repeat(9_000)}.${signature}`,
      "x".repeat(9_000),
    ];

    for (const token of malformed) {
      expect(await gate.verify(token, REQUEST)).toBeNull();
    }
  });

  it("issues unique ids and nonces for identical requests", async () => {
    const gate = new HmacApprovalGate({ secret: "test-secret", now: () => NOW });
    const first = await gate.issue(REQUEST);
    const second = await gate.issue(REQUEST);

    expect(first.grant.id).not.toBe(second.grant.id);
    expect(first.token).not.toBe(second.token);
    expect(decodePayload(first.token).nonce).not.toBe(
      decodePayload(second.token).nonce,
    );
  });

  it("accepts a Uint8Array secret", async () => {
    const gate = new HmacApprovalGate({
      secret: new TextEncoder().encode("bytes-secret"),
      now: () => NOW,
    });
    const issued = await gate.issue(REQUEST);
    expect(await gate.verify(issued.token, REQUEST)).not.toBeNull();
  });

  it("rejects empty secrets and invalid lifetimes", () => {
    expect(() => new HmacApprovalGate({ secret: "" })).toThrow(GapError);
    expect(
      () => new HmacApprovalGate({ secret: new Uint8Array() }),
    ).toThrow(GapError);
    expect(
      () => new HmacApprovalGate({ secret: "test-secret", ttlMs: 0 }),
    ).toThrow(GapError);
    expect(
      () => new HmacApprovalGate({ secret: "test-secret", ttlMs: -1 }),
    ).toThrow(GapError);
  });

  it("rejects invalid issue requests", async () => {
    const gate = new HmacApprovalGate({ secret: "test-secret", now: () => NOW });

    await expect(
      gate.issue({ action: "", args: {}, principalId: PRINCIPAL }),
    ).rejects.toBeInstanceOf(GapError);
    await expect(
      gate.issue({ action: ACTION, args: {}, principalId: "" }),
    ).rejects.toBeInstanceOf(GapError);
    await expect(
      gate.issue({ ...REQUEST, ttlMs: 0 }),
    ).rejects.toBeInstanceOf(GapError);
  });
});
