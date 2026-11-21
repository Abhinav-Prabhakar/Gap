"""API key, JWT, approval-token and human-handoff primitives."""

from __future__ import annotations

import base64
import hmac
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable, Mapping, Sequence
from urllib.parse import quote

import jwt
from jwt import PyJWKClient, PyJWKSet, PyJWTError

from .errors import conflict, invalid_input, not_found
from .types import ApprovalGrant, AuthResult, Principal
from .utils import create_id, hash_value, maybe_await, to_jsonable

__all__ = [
    "ApiKeyAuth",
    "ApiKeyRecord",
    "ComposeAuth",
    "HmacApprovalGate",
    "JwtAuth",
    "MemoryApprovalStore",
    "PendingApproval",
    "bearer_challenge",
    "compose_auth",
    "create_handoff_url",
    "protected_resource_metadata",
    "read_bearer_token",
    "verify_handoff_state",
]

_TOKEN_MAX = 8 * 1024
_PAYLOAD_MAX = 4 * 1024
_SIGNATURE_MAX = 128
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_DEFAULT_APPROVAL_TTL_MS = 10 * 60 * 1000
_DEFAULT_HANDOFF_TTL_MS = 5 * 60 * 1000


# ---------------------------------------------------------------------------
# Header / token helpers
# ---------------------------------------------------------------------------


def _headers(request: Any) -> Mapping[str, Any]:
    if request is None:
        return {}
    headers = getattr(request, "headers", None)
    if headers is None and isinstance(request, Mapping):
        headers = request
    if headers is None:
        return {}
    return headers


def _header(request: Any, name: str) -> str | None:
    headers = _headers(request)
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name)
        if value is None:
            value = getter(name.lower())
        if value is not None:
            return str(value)
    target = name.lower()
    try:
        for key, value in headers.items():
            if str(key).lower() == target and value is not None:
                return str(value)
    except AttributeError:
        return None
    return None


def read_bearer_token(request: Any) -> str | None:
    """Read ``Authorization: Bearer <token>`` case-insensitively."""
    header = _header(request, "authorization")
    if not header:
        return None
    match = re.fullmatch(r"\s*Bearer\s+(\S+)\s*", header, re.IGNORECASE)
    return match.group(1) if match else None


def _merge_scopes(*groups: Sequence[str] | None) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for scope in group or ():
            if scope and scope not in seen:
                seen.add(scope)
                result.append(scope)
    return result


def _unique_strings(values: Sequence[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if isinstance(value, str) and value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


@dataclass(kw_only=True, slots=True)
class ApiKeyRecord:
    """A static API key and the principal it authenticates."""

    key: str
    principal: Principal
    scopes: list[str] | None = None


class ApiKeyAuth:
    """Authenticate requests with API keys.

    Keys are compared by SHA-256 digest in constant time and can be sent as
    ``Authorization: Bearer <key>`` or ``X-API-Key``. A resolver callable may
    be supplied for database-backed keys; it receives the request and returns
    an :class:`ApiKeyRecord` or ``None``.
    """

    def __init__(
        self,
        keys: Sequence[ApiKeyRecord]
        | Callable[[Any], ApiKeyRecord | None | Awaitable[ApiKeyRecord | None]],
        *,
        header: str | None = None,
    ) -> None:
        if header not in {None, "authorization", "x-api-key"}:
            raise invalid_input('header must be "authorization", "x-api-key" or None.')
        self._resolver = keys if callable(keys) else None
        self._static = (
            [] if callable(keys) else [record for record in keys if record.key]
        )
        self._header = header

    @staticmethod
    def _digest(value: str) -> bytes:
        import hashlib

        return hashlib.sha256(value.encode("utf-8")).digest()

    def _candidates(self, request: Any) -> list[str]:
        candidates: list[str] = []
        if self._header in {None, "authorization"}:
            bearer = read_bearer_token(request)
            if bearer:
                candidates.append(bearer)
        if self._header in {None, "x-api-key"}:
            value = _header(request, "x-api-key")
            if value and value.strip():
                candidates.append(value.strip())
        return candidates

    def _result(self, record: ApiKeyRecord, token: str) -> AuthResult:
        has_scopes = record.principal.scopes is not None or record.scopes is not None
        scopes = _merge_scopes(record.principal.scopes, record.scopes)
        principal = replace(
            record.principal,
            scopes=scopes if has_scopes else record.principal.scopes,
            metadata=(
                dict(record.principal.metadata)
                if record.principal.metadata is not None
                else None
            ),
        )
        return AuthResult(
            principal=principal,
            token=token,
            client_id=principal.id,
            scopes=list(scopes) if has_scopes else None,
        )

    async def authenticate(self, request: Any) -> AuthResult | None:
        """Return a principal for a valid key, otherwise ``None``."""
        candidates = self._candidates(request)
        if not candidates:
            return None

        if self._resolver is not None:
            try:
                record = await maybe_await(self._resolver(request))
            except Exception:
                return None
            if record is None or not record.key:
                return None
            expected = self._digest(record.key)
            for candidate in candidates:
                if hmac.compare_digest(self._digest(candidate), expected):
                    return self._result(record, candidate)
            return None

        prepared = [(record, self._digest(record.key)) for record in self._static]
        if not prepared:
            return None
        for candidate in candidates:
            presented = self._digest(candidate)
            matched: ApiKeyRecord | None = None
            # Scan every record so timing does not reveal the matching index.
            for record, digest in prepared:
                if hmac.compare_digest(presented, digest) and matched is None:
                    matched = record
            if matched is not None:
                return self._result(matched, candidate)
        return None

    def challenge(self) -> str:
        """WWW-Authenticate value for a 401."""
        return bearer_challenge()

    def protected_resource_metadata(self) -> dict[str, Any] | None:
        return None


# ---------------------------------------------------------------------------
# JWT resource server
# ---------------------------------------------------------------------------


_PRINCIPAL_TYPES = {"user", "service", "anonymous"}
_ALGORITHMS = {
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
    "HS256",
    "HS384",
    "HS512",
}


def _non_empty_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _principal_from_claims(claims: Mapping[str, Any]) -> Principal | None:
    sub = _non_empty_string(claims.get("sub"))
    if not sub:
        return None
    scopes: list[str] = []
    for key in ("scope", "scp"):
        value = claims.get(key)
        if isinstance(value, str):
            scopes.extend(part for part in re.split(r"\s+", value) if part)
        elif isinstance(value, list):
            scopes.extend(item for item in value if isinstance(item, str) and item)
    principal = Principal(
        id=sub,
        scopes=_unique_strings(scopes) or None,
        tenant_id=_non_empty_string(claims.get("tenant_id"))
        or _non_empty_string(claims.get("tenantId")),
        email=_non_empty_string(claims.get("email")),
        name=_non_empty_string(claims.get("name")),
    )
    if claims.get("type") in _PRINCIPAL_TYPES:
        principal.type = claims["type"]  # type: ignore[assignment]
    return principal


def _normalize_principal(value: Principal | None) -> Principal | None:
    if not isinstance(value, Principal) or not _non_empty_string(value.id):
        return None
    scopes = _unique_strings(value.scopes) if value.scopes is not None else None
    return replace(
        value,
        type=value.type if value.type in _PRINCIPAL_TYPES else None,
        tenant_id=_non_empty_string(value.tenant_id),
        email=_non_empty_string(value.email),
        name=_non_empty_string(value.name),
        scopes=scopes or None,
        metadata=dict(value.metadata) if isinstance(value.metadata, dict) else None,
    )


class JwtAuth:
    """Verify OAuth 2.1 bearer JWTs against a local or remote JWKS.

    Signature, issuer, audience, expiry and the required ``exp`` / ``sub``
    claims are verified by PyJWT. Standard claims are mapped to a
    :class:`Principal`; pass ``map_claims`` to override.
    """

    def __init__(
        self,
        *,
        issuer: str | None = None,
        audience: str | Sequence[str] | None = None,
        jwks_uri: str | None = None,
        jwks: Mapping[str, Any] | None = None,
        clock_tolerance_seconds: float = 0,
        map_claims: Callable[[Mapping[str, Any]], Principal | None] | None = None,
    ) -> None:
        if jwks is None and jwks_uri is None:
            raise invalid_input("jwt_auth requires either jwks or jwks_uri.")
        self.issuer = issuer
        self.audience = (
            list(audience) if isinstance(audience, (list, tuple)) else audience
        )
        self._map_claims = map_claims
        self._leeway = (
            float(clock_tolerance_seconds)
            if isinstance(clock_tolerance_seconds, (int, float))
            and clock_tolerance_seconds > 0
            else 0
        )
        self._local: PyJWKSet | None = None
        self._remote: PyJWKClient | None = None
        try:
            if jwks is not None:
                self._local = PyJWKSet.from_dict(dict(jwks))
            else:
                assert jwks_uri is not None
                self._remote = PyJWKClient(jwks_uri)
        except Exception as error:
            raise invalid_input("Invalid JWKS configuration.") from error

    def _signing_key(self, token: str) -> tuple[Any, str]:
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in _ALGORITHMS:
            raise ValueError("Unsupported JWT algorithm.")
        kid = header.get("kid")
        if self._local is not None:
            candidates = list(self._local.keys)
            if kid is not None:
                candidates = [key for key in candidates if key.key_id == kid]
            if not candidates:
                raise ValueError("No matching JWK.")
            key = candidates[0]
            expected = key.algorithm_name or algorithm
            if algorithm != expected:
                raise ValueError("JWT algorithm does not match the key.")
            return key.key, expected
        assert self._remote is not None
        key = self._remote.get_signing_key_from_jwt(token)
        expected = key.algorithm_name or algorithm
        if algorithm != expected:
            raise ValueError("JWT algorithm does not match the key.")
        return key.key, expected

    async def authenticate(self, request: Any) -> AuthResult | None:
        """Return a principal for a valid JWT, otherwise ``None``."""
        token = read_bearer_token(request)
        if not token or len(token) > 64 * 1024 or token.count(".") != 2:
            return None
        try:
            key, algorithm = self._signing_key(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                issuer=self.issuer,
                audience=self.audience,
                leeway=self._leeway,
                options={
                    "require": ["exp", "sub"],
                    "verify_aud": self.audience is not None,
                    "verify_iss": self.issuer is not None,
                },
            )
        except (PyJWTError, ValueError, KeyError, TypeError):
            return None
        except Exception:
            return None
        if not isinstance(claims, Mapping):
            return None

        if self._map_claims is not None:
            try:
                principal = _normalize_principal(
                    await maybe_await(self._map_claims(claims))
                )
            except Exception:
                return None
        else:
            principal = _normalize_principal(_principal_from_claims(claims))
        if principal is None:
            return None

        exp = claims.get("exp")
        if (
            isinstance(exp, bool)
            or not isinstance(exp, (int, float))
            or not math.isfinite(exp)
        ):
            return None
        client_id = _non_empty_string(claims.get("client_id")) or _non_empty_string(
            claims.get("azp")
        )
        return AuthResult(
            principal=principal,
            token=token,
            client_id=client_id,
            scopes=list(principal.scopes) if principal.scopes else None,
            expires_at=int(exp * 1000),
        )

    def challenge(self) -> str:
        return bearer_challenge()

    def protected_resource_metadata(self) -> dict[str, Any] | None:
        return None


# ---------------------------------------------------------------------------
# Composition and metadata
# ---------------------------------------------------------------------------


class ComposeAuth:
    """Try providers in order; the first successful result wins."""

    def __init__(self, providers: Sequence[Any]) -> None:
        if not providers:
            raise invalid_input("compose_auth requires at least one provider.")
        self.providers = list(providers)

    async def authenticate(self, request: Any) -> AuthResult | None:
        for provider in self.providers:
            try:
                result = await maybe_await(provider.authenticate(request))
            except Exception:
                continue
            if result is not None:
                return result
        return None

    def challenge(self) -> str:
        for provider in self.providers:
            challenge = getattr(provider, "challenge", None)
            if callable(challenge):
                return challenge()
        return bearer_challenge()

    def protected_resource_metadata(self) -> dict[str, Any] | None:
        for provider in self.providers:
            method = getattr(provider, "protected_resource_metadata", None)
            if callable(method):
                metadata = method()
                if metadata is not None:
                    return metadata
        return None


def compose_auth(*providers: Any) -> ComposeAuth:
    """Compose multiple auth providers, trying each in order."""
    return ComposeAuth(providers)


def _quote_header_value(value: str) -> str:
    sanitized = re.sub(r"[\x00-\x1f\x7f]", "", value)
    return sanitized.replace("\\", "\\\\").replace('"', '\\"')


def bearer_challenge(
    *,
    realm: str = "gap",
    error: str | None = None,
    resource_metadata_url: str | None = None,
) -> str:
    """Build a quoted ``WWW-Authenticate: Bearer`` challenge."""
    parts = [f'realm="{_quote_header_value(realm)}"']
    if error is not None:
        parts.append(f'error="{_quote_header_value(error)}"')
    if resource_metadata_url is not None:
        parts.append(
            f'resource_metadata="{_quote_header_value(resource_metadata_url)}"'
        )
    return "Bearer " + ", ".join(parts)


def protected_resource_metadata(
    *,
    resource: str,
    authorization_servers: Sequence[str],
    scopes_supported: Sequence[str] | None = None,
    resource_documentation: str | None = None,
) -> dict[str, Any]:
    """Build an RFC 9728 protected-resource metadata document."""
    return {
        "resource": resource,
        "authorization_servers": list(authorization_servers),
        "scopes_supported": list(scopes_supported or ()),
        "bearer_methods_supported": ["header"],
        "resource_documentation": resource_documentation or resource,
    }


# ---------------------------------------------------------------------------
# Compact tokens
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    if not value or not _B64URL.fullmatch(value) or len(value) % 4 == 1:
        raise ValueError("Invalid base64url encoding.")
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _hmac(secret: bytes, data: bytes) -> bytes:
    return hmac.new(secret, data, "sha256").digest()


def _compact_json(value: Any) -> str:
    return json.dumps(to_jsonable(value), ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Approval gate
# ---------------------------------------------------------------------------


class HmacApprovalGate:
    """Issue and verify compact human-approval grants.

    Token format: ``v1.<base64url(json payload)>.<base64url(hmac-sha256)>``.
    The payload binds the grant to the exact action, principal and canonical
    argument hash. Verification recomputes the hash, rejects expired grants and
    compares the signature in constant time.
    """

    def __init__(
        self,
        secret: str | bytes,
        *,
        ttl_ms: int = _DEFAULT_APPROVAL_TTL_MS,
        now: Callable[[], float] | None = None,
    ) -> None:
        secret_bytes = (
            secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        )
        if not secret_bytes:
            raise invalid_input("Approval gate secret must not be empty.")
        if (
            not isinstance(ttl_ms, (int, float))
            or not math.isfinite(ttl_ms)
            or ttl_ms <= 0
        ):
            raise invalid_input("Approval ttl_ms must be a positive number.")
        self._secret = secret_bytes
        self.ttl_ms = int(ttl_ms)
        self._now = now or (lambda: time.time() * 1000)

    def _sign(self, segment: str) -> str:
        return _b64url_encode(_hmac(self._secret, f"v1.{segment}".encode("utf-8")))

    def issue(
        self,
        *,
        action: str,
        args: Any,
        principal_id: str,
        ttl_ms: int | None = None,
        approved_by: str | None = None,
    ) -> tuple[str, ApprovalGrant]:
        """Create a signed grant and its compact token."""
        if not action or not principal_id:
            raise invalid_input("Approval requires an action and principal_id.")
        ttl = self.ttl_ms if ttl_ms is None else ttl_ms
        if not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or ttl <= 0:
            raise invalid_input("Approval ttl_ms must be a positive number.")
        iat = int(self._now())
        exp = iat + max(1, int(ttl))
        payload = {
            "id": create_id("apr"),
            "action": action,
            "argsHash": hash_value(args),
            "principalId": principal_id,
            "approvedBy": approved_by or principal_id,
            "iat": iat,
            "exp": exp,
            "nonce": _b64url_encode(secrets.token_bytes(16)),
        }
        segment = _b64url_encode(_compact_json(payload).encode("utf-8"))
        token = f"v1.{segment}.{self._sign(segment)}"
        grant = ApprovalGrant(
            id=payload["id"],
            action=action,
            args_hash=payload["argsHash"],
            approved_by=payload["approvedBy"],
            issued_at=iat,
            expires_at=exp,
        )
        return token, grant

    def verify(
        self,
        token: str,
        *,
        action: str,
        args: Any,
        principal_id: str,
    ) -> ApprovalGrant | None:
        """Verify a token against the current action, principal and arguments."""
        if (
            not isinstance(token, str)
            or not token
            or len(token) > _TOKEN_MAX
            or token.count(".") != 2
        ):
            return None
        version, segment, signature = token.split(".")
        if (
            version != "v1"
            or not segment
            or not signature
            or len(segment) > _PAYLOAD_MAX
            or len(signature) > _SIGNATURE_MAX
        ):
            return None
        try:
            provided = _b64url_decode(signature)
            expected = _hmac(self._secret, f"v1.{segment}".encode("utf-8"))
        except ValueError:
            return None
        if len(provided) != 32 or not hmac.compare_digest(provided, expected):
            return None
        try:
            payload = json.loads(_b64url_decode(segment).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, Mapping):
            return None
        identifier = _non_empty_string(payload.get("id"))
        payload_action = _non_empty_string(payload.get("action"))
        args_hash = _non_empty_string(payload.get("argsHash"))
        payload_principal = _non_empty_string(payload.get("principalId"))
        approved_by = _non_empty_string(payload.get("approvedBy"))
        nonce = _non_empty_string(payload.get("nonce"))
        iat = payload.get("iat")
        exp = payload.get("exp")
        if (
            not identifier
            or not payload_action
            or not args_hash
            or not payload_principal
            or not approved_by
            or not nonce
            or isinstance(iat, bool)
            or not isinstance(iat, int)
            or isinstance(exp, bool)
            or not isinstance(exp, int)
            or exp <= iat
        ):
            return None
        current = self._now()
        if not math.isfinite(current) or current >= exp:
            return None
        if payload_action != action or payload_principal != principal_id:
            return None
        try:
            expected_hash = hash_value(args)
        except TypeError:
            return None
        if not hmac.compare_digest(
            args_hash.encode("utf-8"), expected_hash.encode("utf-8")
        ):
            return None
        return ApprovalGrant(
            id=identifier,
            action=payload_action,
            args_hash=args_hash,
            approved_by=approved_by,
            issued_at=iat,
            expires_at=exp,
        )


# ---------------------------------------------------------------------------
# Pending approval store
# ---------------------------------------------------------------------------


@dataclass(kw_only=True, slots=True)
class PendingApproval:
    """One parked invocation awaiting (or holding) human approval."""

    id: str
    action: str
    principal_id: str
    args_hash: str
    status: str
    created_at: int
    expires_at: int
    approved_by: str | None = None
    approved_at: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "approvalId": self.id,
            "action": self.action,
            "principalId": self.principal_id,
            "argsHash": self.args_hash,
            "status": self.status,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "approvedBy": self.approved_by,
            "approvedAt": self.approved_at,
        }

    def to_grant(self) -> ApprovalGrant:
        return ApprovalGrant(
            id=self.id,
            action=self.action,
            args_hash=self.args_hash,
            approved_by=self.approved_by or self.principal_id,
            issued_at=self.approved_at or self.created_at,
            expires_at=self.expires_at,
        )


class MemoryApprovalStore:
    """In-memory pending approvals for one process.

    Multi-replica deployments should implement the same methods with Redis or
    Postgres so a human can approve on one replica and the agent can retry on
    another.
    """

    def __init__(
        self,
        *,
        ttl_ms: int = _DEFAULT_APPROVAL_TTL_MS,
        now: Callable[[], float] | None = None,
    ) -> None:
        if (
            isinstance(ttl_ms, bool)
            or not isinstance(ttl_ms, (int, float))
            or not math.isfinite(ttl_ms)
            or ttl_ms <= 0
        ):
            raise invalid_input("Approval ttl_ms must be a positive number.")
        self.ttl_ms = int(ttl_ms)
        self._now = now or (lambda: time.time() * 1000)
        self._records: dict[str, PendingApproval] = {}

    def _refresh(self, record: PendingApproval) -> PendingApproval:
        if record.status == "pending" and self._now() >= record.expires_at:
            record.status = "expired"
        return record

    def create(
        self,
        *,
        action: str,
        principal_id: str,
        args_hash: str,
        ttl_ms: int | None = None,
    ) -> PendingApproval:
        """Park a call and return its pending record."""
        now = int(self._now())
        ttl = ttl_ms if ttl_ms is not None else self.ttl_ms
        record = PendingApproval(
            id=create_id("apr"),
            action=action,
            principal_id=principal_id,
            args_hash=args_hash,
            status="pending",
            created_at=now,
            expires_at=now + max(1, int(ttl)),
        )
        self._records[record.id] = record
        return record

    def get(
        self, approval_id: str, *, include_expired: bool = False
    ) -> PendingApproval | None:
        """Look up one approval."""
        record = self._records.get(approval_id)
        if record is None:
            return None
        self._refresh(record)
        if record.status == "expired" and not include_expired:
            return None
        return record

    def approve(
        self, approval_id: str, approved_by: str | None = None
    ) -> PendingApproval:
        """Approve a pending call; idempotent for an already-approved record."""
        record = self.get(approval_id)
        if record is None:
            raise not_found(f'Unknown or expired approval "{approval_id}".')
        if record.status == "consumed":
            raise conflict("This approval has already been used.")
        if record.status == "denied":
            raise conflict("This approval was denied.")
        if record.status == "pending":
            record.status = "approved"
            record.approved_by = approved_by or record.principal_id
            record.approved_at = int(self._now())
        return record

    def deny(self, approval_id: str, denied_by: str | None = None) -> PendingApproval:
        """Deny a pending call."""
        record = self.get(approval_id)
        if record is None:
            raise not_found(f'Unknown or expired approval "{approval_id}".')
        record.status = "denied"
        record.approved_by = denied_by
        record.approved_at = int(self._now())
        return record

    def find_approved(
        self, *, action: str, principal_id: str, args_hash: str
    ) -> PendingApproval | None:
        """Find an approved, unexpired record matching exactly."""
        for record in list(self._records.values()):
            self._refresh(record)
            if (
                record.status == "approved"
                and record.action == action
                and record.principal_id == principal_id
                and record.args_hash == args_hash
            ):
                return record
        return None

    def consume(self, approval_id: str) -> PendingApproval | None:
        """Mark an approved record consumed."""
        record = self.get(approval_id)
        if record is None or record.status != "approved":
            return None
        record.status = "consumed"
        return record

    def list(self, status: str | None = None) -> list[PendingApproval]:
        """List records, updating expired states, oldest first."""
        records = []
        for record in self._records.values():
            self._refresh(record)
            if status is None or record.status == status:
                records.append(record)
        records.sort(key=lambda record: (record.created_at, record.id))
        return records

    def clear(self) -> None:
        """Remove all records."""
        self._records.clear()


# ---------------------------------------------------------------------------
# Handoff links
# ---------------------------------------------------------------------------


def create_handoff_url(
    *,
    base_url: str,
    action: str,
    args: Any,
    secret: str | bytes,
    ttl_ms: int = _DEFAULT_HANDOFF_TTL_MS,
    path: str = "/",
    now: Callable[[], float] | None = None,
) -> str:
    """Create a signed, expiring human-handoff link.

    Token format matches the DOM package:
    ``v1.<base64url(json)>.<base64url(hmac-sha256)>`` with payload
    ``{action, args, iat, exp, nonce}``. Arguments are never placed in the URL.
    """
    if not action or not action.strip():
        raise invalid_input("A handoff URL needs an action name.")
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    if not secret_bytes:
        raise invalid_input("A handoff secret is required.")
    if not isinstance(ttl_ms, (int, float)) or not math.isfinite(ttl_ms) or ttl_ms <= 0:
        raise invalid_input("Handoff ttl_ms must be a positive number.")
    clock = now or (lambda: time.time() * 1000)
    iat = int(clock())
    payload = {
        "action": action,
        "args": to_jsonable(args if args is not None else {}),
        "iat": iat,
        "exp": iat + max(1, int(ttl_ms)),
        "nonce": _b64url_encode(secrets.token_bytes(12)),
    }
    segment = _b64url_encode(_compact_json(payload).encode("utf-8"))
    signature = _b64url_encode(_hmac(secret_bytes, f"v1.{segment}".encode("utf-8")))
    token = f"v1.{segment}.{signature}"

    base = base_url.rstrip("/")
    suffix = path if path.startswith("/") else f"/{path}"
    separator = "&" if "?" in suffix else "?"
    return f"{base}{suffix}{separator}gap_state={quote(token, safe='')}"


def verify_handoff_state(
    token: str, secret: str | bytes, *, now: Callable[[], float] | None = None
) -> dict[str, Any] | None:
    """Verify a handoff token; returns the payload or ``None``."""
    try:
        secret_bytes = (
            secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        )
        if not token or not secret_bytes or token.count(".") != 2:
            return None
        version, segment, signature = token.split(".")
        if version != "v1" or not segment or not signature:
            return None
        provided = _b64url_decode(signature)
        expected = _hmac(secret_bytes, f"v1.{segment}".encode("utf-8"))
        if not hmac.compare_digest(provided, expected):
            return None
        payload = json.loads(_b64url_decode(segment).decode("utf-8"))
        if not isinstance(payload, Mapping):
            return None
        action = payload.get("action")
        iat = payload.get("iat")
        exp = payload.get("exp")
        nonce = payload.get("nonce")
        if (
            not isinstance(action, str)
            or not action
            or isinstance(iat, bool)
            or not isinstance(iat, (int, float))
            or isinstance(exp, bool)
            or not isinstance(exp, (int, float))
            or not math.isfinite(exp)
            or exp < iat
            or not isinstance(nonce, str)
            or not nonce
        ):
            return None
        clock = now or (lambda: time.time() * 1000)
        if clock() >= exp:
            return None
        return dict(payload)
    except Exception:
        return None
