import { createServer } from "node:http";
import { beforeAll, describe, expect, it } from "vitest";
import { SignJWT, decodeJwt, exportJWK, generateKeyPair, type JWK } from "jose";
import { jwtAuth, type JwtAuthOptions } from "../src/index";

const ISSUER = "https://issuer.example.test";
const AUDIENCE = "https://api.example.test/mcp";
const KEY_ID = "test-key";

let privateKey: CryptoKey;
let wrongKey: CryptoKey;
let jwks: { keys: JWK[] };

beforeAll(async () => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  privateKey = pair.privateKey;
  const publicJwk = await exportJWK(pair.publicKey);
  jwks = {
    keys: [{ ...publicJwk, kid: KEY_ID, alg: "ES256", use: "sig" }],
  };
  const other = await generateKeyPair("ES256", { extractable: true });
  wrongKey = other.privateKey;
});

interface SignOptions {
  issuer?: string;
  audience?: string | string[];
  expiresIn?: string | number | null;
  key?: CryptoKey;
}

async function sign(
  claims: Record<string, unknown>,
  options: SignOptions = {},
): Promise<string> {
  const builder = new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: KEY_ID })
    .setIssuedAt()
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? AUDIENCE);
  if (options.expiresIn !== null) {
    builder.setExpirationTime(options.expiresIn ?? "1h");
  }
  return builder.sign(options.key ?? privateKey);
}

function provider(overrides: Partial<JwtAuthOptions> = {}) {
  return jwtAuth({
    jwks,
    issuer: ISSUER,
    audience: AUDIENCE,
    ...overrides,
  });
}

function request(token: string): Request {
  return new Request("https://api.example.test/mcp", {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
  });
}

function base64Url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

describe("jwtAuth", () => {
  it("verifies a token and maps standard claims", async () => {
    const token = await sign({
      sub: "user_1",
      scope: "invoices.read invoices.write",
      tenant_id: "tenant_1",
      email: "alice@example.test",
      name: "Alice",
      type: "service",
      client_id: "client_1",
    });

    const result = await provider().authenticate(request(token));
    const decoded = decodeJwt(token);

    expect(result).not.toBeNull();
    expect(result?.principal).toEqual({
      id: "user_1",
      type: "service",
      tenantId: "tenant_1",
      scopes: ["invoices.read", "invoices.write"],
      email: "alice@example.test",
      name: "Alice",
    });
    expect(result?.scopes).toEqual(["invoices.read", "invoices.write"]);
    expect(result?.token).toBe(token);
    expect(result?.clientId).toBe("client_1");
    expect(result?.expiresAt).toBe((decoded.exp as number) * 1000);
  });

  it("maps scp arrays and camelCase tenant claims", async () => {
    const token = await sign({
      sub: "svc_1",
      scp: ["billing.read", "billing.write"],
      tenantId: "tenant_2",
      type: "user",
    });

    const result = await provider().authenticate(request(token));

    expect(result?.principal.scopes).toEqual(["billing.read", "billing.write"]);
    expect(result?.principal.tenantId).toBe("tenant_2");
    expect(result?.principal.type).toBe("user");
  });

  it("merges and de-duplicates scope and scp claims", async () => {
    const token = await sign({
      sub: "user_1",
      scope: "read write",
      scp: ["write", "admin"],
    });

    const result = await provider().authenticate(request(token));
    expect(result?.principal.scopes).toEqual(["read", "write", "admin"]);
  });

  it("rejects a token with the wrong audience", async () => {
    const token = await sign({ sub: "user_1" }, { audience: "other-api" });
    expect(await provider().authenticate(request(token))).toBeNull();
  });

  it("rejects a token with the wrong issuer", async () => {
    const token = await sign(
      { sub: "user_1" },
      { issuer: "https://evil.example.test" },
    );
    expect(await provider().authenticate(request(token))).toBeNull();
  });

  it("rejects expired tokens but honours clock tolerance", async () => {
    const token = await sign(
      { sub: "user_1" },
      { expiresIn: Math.floor(Date.now() / 1000) - 5 },
    );

    expect(await provider().authenticate(request(token))).toBeNull();
    expect(
      await provider({ clockToleranceSeconds: 30 }).authenticate(
        request(token),
      ),
    ).not.toBeNull();
  });

  it("rejects tokens without sub or exp", async () => {
    const noSub = await sign({ email: "alice@example.test" });
    const noExp = await sign({ sub: "user_1" }, { expiresIn: null });

    expect(await provider().authenticate(request(noSub))).toBeNull();
    expect(await provider().authenticate(request(noExp))).toBeNull();
  });

  it("rejects tokens signed by a different key", async () => {
    const token = await sign({ sub: "user_1" }, { key: wrongKey });
    expect(await provider().authenticate(request(token))).toBeNull();
  });

  it("rejects unsigned alg:none tokens", async () => {
    const token = `${base64Url({ alg: "none", typ: "JWT" })}.${base64Url({
      sub: "user_1",
      exp: Math.floor(Date.now() / 1000) + 60,
    })}.`;
    expect(await provider().authenticate(request(token))).toBeNull();
  });

  it("rejects malformed authorization headers", async () => {
    const providerUnderTest = provider();
    expect(
      await providerUnderTest.authenticate(
        new Request("https://api.example.test/mcp", {
          headers: { authorization: "Basic abc" },
        }),
      ),
    ).toBeNull();
    expect(
      await providerUnderTest.authenticate(
        new Request("https://api.example.test/mcp", {
          headers: { authorization: "Bearer not-a-jwt" },
        }),
      ),
    ).toBeNull();
    expect(
      await providerUnderTest.authenticate(
        new Request("https://api.example.test/mcp"),
      ),
    ).toBeNull();
  });

  it("lets a custom mapper override claims", async () => {
    const token = await sign({
      sub: "user_1",
      email: "alice@example.test",
      scope: "ignored",
    });

    const result = await provider({
      mapClaims: (claims) => ({
        id: `custom:${String(claims.email)}`,
        scopes: ["custom.read"],
        metadata: { issuer: claims.iss },
      }),
    }).authenticate(request(token));

    expect(result?.principal.id).toBe("custom:alice@example.test");
    expect(result?.principal.scopes).toEqual(["custom.read"]);
    expect(result?.scopes).toEqual(["custom.read"]);
    expect(result?.principal.metadata).toEqual({ issuer: ISSUER });
  });

  it("rejects when a custom mapper returns null or throws", async () => {
    const token = await sign({ sub: "user_1" });

    expect(
      await provider({ mapClaims: () => null }).authenticate(request(token)),
    ).toBeNull();
    expect(
      await provider({
        mapClaims: () => {
          throw new Error("bad claims");
        },
      }).authenticate(request(token)),
    ).toBeNull();
  });

  it("rejects a custom mapper result without a usable id", async () => {
    const token = await sign({ sub: "user_1" });
    expect(
      await provider({
        mapClaims: () => ({ id: "   " }),
      }).authenticate(request(token)),
    ).toBeNull();
  });

  it("requires JWKS configuration", () => {
    expect(() => jwtAuth({ issuer: ISSUER })).toThrow();
    expect(() => jwtAuth({ jwksUri: "not a url", issuer: ISSUER })).toThrow();
  });

  it("verifies tokens against a remote JWKS endpoint", async () => {
    const server = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(jwks));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });

    try {
      const address = server.address();
      if (!address || typeof address === "string") {
        throw new Error("Expected an IP socket address.");
      }
      const remote = jwtAuth({
        jwksUri: `http://127.0.0.1:${address.port}/jwks.json`,
        issuer: ISSUER,
        audience: AUDIENCE,
      });
      const token = await sign({ sub: "remote_user" });
      const result = await remote.authenticate(request(token));
      expect(result?.principal.id).toBe("remote_user");
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
});
