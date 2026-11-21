"""API key auth, JWT verification, approvals, handoff and audit sinks."""

from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.requests import Request

from gapmcp import (
    ApiKeyAuth,
    ApiKeyRecord,
    ApprovalGrant,
    GapError,
    HmacApprovalGate,
    JwtAuth,
    MemoryApprovalStore,
    MemoryAuditLog,
    Principal,
    bearer_challenge,
    compose_auth,
    create_audit_event,
    create_handoff_url,
    protected_resource_metadata,
    read_bearer_token,
    verify_handoff_state,
)
from gapmcp.audit import JsonlAuditLog


def request_with_headers(**headers: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/mcp",
            "headers": [
                (name.lower().encode("latin-1"), value.encode("latin-1"))
                for name, value in headers.items()
            ],
        }
    )


def key_auth() -> ApiKeyAuth:
    return ApiKeyAuth(
        [
            ApiKeyRecord(
                key="key-one",
                principal=Principal(id="usr_1", scopes=["invoices:read"]),
            ),
            ApiKeyRecord(
                key="key-two",
                principal=Principal(id="usr_2", scopes=["invoices:write"]),
                scopes=["reports:read"],
            ),
        ]
    )


async def test_api_key_bearer_and_x_api_key() -> None:
    auth = key_auth()
    bearer = await auth.authenticate(
        request_with_headers(Authorization="Bearer key-one")
    )
    assert bearer is not None
    assert bearer.principal.id == "usr_1"
    assert bearer.scopes == ["invoices:read"]

    alternate = await auth.authenticate(
        request_with_headers(**{"X-API-Key": "key-two"})
    )
    assert alternate is not None
    assert alternate.principal.id == "usr_2"
    assert alternate.scopes == ["invoices:write", "reports:read"]


async def test_api_key_rejects_missing_and_wrong_keys() -> None:
    auth = key_auth()
    assert await auth.authenticate(request_with_headers()) is None
    assert (
        await auth.authenticate(request_with_headers(Authorization="Bearer not-a-key"))
        is None
    )
    assert (
        await auth.authenticate(request_with_headers(Authorization="Basic key-one"))
        is None
    )


async def test_api_key_header_restriction_and_resolver() -> None:
    only_header = ApiKeyAuth(
        [ApiKeyRecord(key="key-one", principal=Principal(id="usr_1"))],
        header="x-api-key",
    )
    assert (
        await only_header.authenticate(
            request_with_headers(Authorization="Bearer key-one")
        )
        is None
    )
    assert (
        await only_header.authenticate(request_with_headers(**{"X-API-Key": "key-one"}))
        is not None
    )

    async def resolver(request):
        if request.headers.get("x-api-key") == "dynamic":
            return ApiKeyRecord(key="dynamic", principal=Principal(id="usr_dynamic"))
        return None

    dynamic = ApiKeyAuth(resolver)
    result = await dynamic.authenticate(
        request_with_headers(**{"X-API-Key": "dynamic"})
    )
    assert result is not None
    assert result.principal.id == "usr_dynamic"
    assert (
        await dynamic.authenticate(request_with_headers(**{"X-API-Key": "wrong"}))
        is None
    )


async def test_read_bearer_token_is_case_insensitive() -> None:
    request = request_with_headers(Authorization="bearer abc.def.ghi")
    assert read_bearer_token(request) == "abc.def.ghi"
    assert read_bearer_token(request_with_headers()) is None


@pytest.fixture(scope="module")
def rsa_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
    return private_key, {"keys": [jwk]}


def make_token(private_key, **overrides) -> str:
    claims = {
        "sub": "usr_jwt",
        "scope": "invoices:read reports:read",
        "tenant_id": "ten_1",
        "email": "user@example.com",
        "name": "JWT User",
        "exp": int(time.time()) + 300,
        "iss": "https://issuer.example.com",
        "aud": "https://api.example.com/mcp",
    }
    claims.update(overrides)
    return jwt.encode(
        claims, private_key, algorithm="RS256", headers={"kid": "test-key"}
    )


async def test_jwt_verification_and_claim_mapping(rsa_material) -> None:
    private_key, jwks = rsa_material
    auth = JwtAuth(
        issuer="https://issuer.example.com",
        audience="https://api.example.com/mcp",
        jwks=jwks,
    )
    token = make_token(private_key)
    result = await auth.authenticate(
        request_with_headers(Authorization=f"Bearer {token}")
    )
    assert result is not None
    assert result.principal.id == "usr_jwt"
    assert result.principal.tenant_id == "ten_1"
    assert result.principal.email == "user@example.com"
    assert result.principal.name == "JWT User"
    assert result.scopes == ["invoices:read", "reports:read"]
    assert result.token == token
    assert result.expires_at and result.expires_at > int(time.time() * 1000)


async def test_jwt_rejects_bad_signature_expiry_issuer_and_audience(
    rsa_material,
) -> None:
    private_key, jwks = rsa_material
    auth = JwtAuth(
        issuer="https://issuer.example.com",
        audience="https://api.example.com/mcp",
        jwks=jwks,
    )

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert (
        await auth.authenticate(
            request_with_headers(Authorization=f"Bearer {make_token(other_key)}")
        )
        is None
    )
    assert (
        await auth.authenticate(
            request_with_headers(
                Authorization=f"Bearer {make_token(private_key, exp=int(time.time()) - 5)}"
            )
        )
        is None
    )
    assert (
        await auth.authenticate(
            request_with_headers(
                Authorization=(
                    "Bearer " + make_token(private_key, iss="https://evil.example.com")
                )
            )
        )
        is None
    )
    assert (
        await auth.authenticate(
            request_with_headers(
                Authorization=(
                    "Bearer " + make_token(private_key, aud="other-audience")
                )
            )
        )
        is None
    )
    assert (
        await auth.authenticate(request_with_headers(Authorization="Bearer not-a-jwt"))
        is None
    )


async def test_jwt_requires_subject_and_expiry(rsa_material) -> None:
    private_key, jwks = rsa_material
    auth = JwtAuth(jwks=jwks)
    no_sub = jwt.encode(
        {"exp": int(time.time()) + 60},
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    no_exp = jwt.encode(
        {"sub": "usr_jwt"},
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    assert (
        await auth.authenticate(request_with_headers(Authorization=f"Bearer {no_sub}"))
        is None
    )
    assert (
        await auth.authenticate(request_with_headers(Authorization=f"Bearer {no_exp}"))
        is None
    )


async def test_jwt_custom_claim_mapping(rsa_material) -> None:
    private_key, jwks = rsa_material

    def map_claims(claims):
        return Principal(
            id=f"mapped:{claims['sub']}",
            type="service",
            scopes=["custom"],
        )

    auth = JwtAuth(jwks=jwks, map_claims=map_claims)
    result = await auth.authenticate(
        request_with_headers(Authorization=f"Bearer {make_token(private_key)}")
    )
    assert result is not None
    assert result.principal.id == "mapped:usr_jwt"
    assert result.principal.type == "service"
    assert result.scopes == ["custom"]


def test_auth_challenge_and_metadata() -> None:
    challenge = bearer_challenge(
        realm="billing", resource_metadata_url="https://api.example.com/meta"
    )
    assert challenge.startswith("Bearer ")
    assert 'realm="billing"' in challenge
    assert 'resource_metadata="https://api.example.com/meta"' in challenge

    metadata = protected_resource_metadata(
        resource="https://api.example.com/mcp",
        authorization_servers=["https://issuer.example.com"],
        scopes_supported=["invoices:read"],
    )
    assert metadata["resource"] == "https://api.example.com/mcp"
    assert metadata["authorization_servers"] == ["https://issuer.example.com"]
    assert metadata["bearer_methods_supported"] == ["header"]


async def test_compose_auth_tries_in_order() -> None:
    auth = compose_auth(
        key_auth(),
        ApiKeyAuth(
            [ApiKeyRecord(key="fallback", principal=Principal(id="usr_fallback"))]
        ),
    )
    result = await auth.authenticate(request_with_headers(**{"X-API-Key": "key-two"}))
    assert result is not None
    assert result.principal.id == "usr_2"
    assert await auth.authenticate(request_with_headers()) is None


def test_hmac_approval_roundtrip_and_binding() -> None:
    gate = HmacApprovalGate("test-secret", ttl_ms=60_000)
    token, grant = gate.issue(
        action="invoices.delete",
        args={"id": "inv_1", "amount": 42},
        principal_id="usr_1",
        approved_by="alice@example.com",
    )
    assert token.startswith("v1.")
    assert isinstance(grant, ApprovalGrant)
    assert grant.action == "invoices.delete"

    verified = gate.verify(
        token,
        action="invoices.delete",
        args={"amount": 42, "id": "inv_1"},
        principal_id="usr_1",
    )
    assert verified is not None
    assert verified.id == grant.id
    assert verified.approved_by == "alice@example.com"

    assert (
        gate.verify(
            token,
            action="invoices.delete",
            args={"id": "inv_1", "amount": 43},
            principal_id="usr_1",
        )
        is None
    )
    assert (
        gate.verify(
            token,
            action="invoices.delete",
            args={"id": "inv_1", "amount": 42},
            principal_id="usr_2",
        )
        is None
    )


def test_hmac_approval_tamper_and_expiry() -> None:
    clock = [1_000_000.0]
    gate = HmacApprovalGate("test-secret", ttl_ms=1_000, now=lambda: clock[0])
    token, _ = gate.issue(
        action="invoices.delete", args={"id": "inv_1"}, principal_id="usr_1"
    )
    version, payload, signature = token.split(".")
    tampered = f"{version}.{payload[:-2]}AA.{signature}"
    assert (
        gate.verify(
            tampered,
            action="invoices.delete",
            args={"id": "inv_1"},
            principal_id="usr_1",
        )
        is None
    )

    clock[0] += 1_001
    assert (
        gate.verify(
            token,
            action="invoices.delete",
            args={"id": "inv_1"},
            principal_id="usr_1",
        )
        is None
    )


def test_approval_store_lifecycle() -> None:
    store = MemoryApprovalStore()
    record = store.create(
        action="invoices.delete",
        principal_id="usr_1",
        args_hash="abc",
    )
    assert record.status == "pending"
    assert (
        store.find_approved(
            action="invoices.delete", principal_id="usr_1", args_hash="abc"
        )
        is None
    )

    approved = store.approve(record.id, "alice")
    assert approved.status == "approved"
    found = store.find_approved(
        action="invoices.delete", principal_id="usr_1", args_hash="abc"
    )
    assert found is not None and found.id == record.id
    assert store.consume(record.id) is not None
    assert store.consume(record.id) is None
    assert store.get(record.id).status == "consumed"  # type: ignore[union-attr]

    with pytest.raises(GapError) as missing:
        store.approve("apr_missing")
    assert missing.value.code == "NOT_FOUND"


def test_approval_store_deny_and_expiry() -> None:
    clock = [1_000.0]
    store = MemoryApprovalStore(ttl_ms=500, now=lambda: clock[0])
    record = store.create(
        action="invoices.delete", principal_id="usr_1", args_hash="abc"
    )
    store.deny(record.id, "alice")
    assert store.get(record.id).status == "denied"  # type: ignore[union-attr]
    with pytest.raises(GapError):
        store.approve(record.id)

    pending = store.create(
        action="invoices.delete", principal_id="usr_1", args_hash="abc"
    )
    clock[0] += 501
    assert store.get(pending.id) is None
    assert store.get(pending.id, include_expired=True).status == "expired"  # type: ignore[union-attr]


def test_handoff_url_roundtrip_tamper_and_expiry() -> None:
    url = create_handoff_url(
        base_url="https://app.example.com",
        action="invoices.create",
        args={"customerId": "cus_1", "amount": 10},
        secret="handoff-secret",
        ttl_ms=60_000,
        path="/invoices/new",
    )
    parsed = urlparse(url)
    assert parsed.path == "/invoices/new"
    token = parse_qs(parsed.query)["gap_state"][0]
    payload = verify_handoff_state(token, "handoff-secret")
    assert payload is not None
    assert payload["action"] == "invoices.create"
    assert payload["args"] == {"customerId": "cus_1", "amount": 10}
    assert verify_handoff_state(token, "wrong-secret") is None

    version, body, signature = token.split(".")
    tampered = f"{version}.{body[:-2]}AA.{signature}"
    assert verify_handoff_state(tampered, "handoff-secret") is None

    clock = [1_000.0]
    expired = create_handoff_url(
        base_url="https://app.example.com",
        action="invoices.create",
        args={},
        secret="handoff-secret",
        ttl_ms=100,
        now=lambda: clock[0],
    )
    expired_token = parse_qs(urlparse(expired).query)["gap_state"][0]
    assert (
        verify_handoff_state(
            expired_token, "handoff-secret", now=lambda: clock[0] + 101
        )
        is None
    )


def test_audit_sinks_and_event_shape(tmp_path) -> None:
    memory = MemoryAuditLog(max=2)
    for index in range(3):
        memory.record(
            create_audit_event(
                action="invoices.create",
                principal_id="usr_1",
                decision="allowed",
                args_hash=f"hash-{index}",
                trace_id="trace_1",
            )
        )
    assert len(memory.events) == 2
    assert memory.list()[0].args_hash == "hash-1"
    memory.clear()
    assert memory.list() == []

    path = tmp_path / "audit.jsonl"
    with JsonlAuditLog(path) as sink:
        sink.record(
            create_audit_event(
                action="invoices.create",
                principal_id="usr_1",
                decision="allowed",
                tenant_id="ten_1",
                args_hash="hash",
                duration_ms=12.5,
            )
        )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["principalId"] == "usr_1"
    assert event["tenantId"] == "ten_1"
    assert event["durationMs"] == 12.5
