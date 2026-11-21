"""HTTP transport: health, metadata, authentication and CORS."""

from __future__ import annotations

from starlette.testclient import TestClient

from gapmcp import (
    ApiKeyAuth,
    ApiKeyRecord,
    Principal,
    create_registry,
    create_server,
    define_action,
)


def make_server(**options):
    action = define_action(
        lambda input, ctx: {"ok": True},
        name="demo.ping",
        description="A tiny action used by the HTTP transport tests.",
    )
    auth = ApiKeyAuth(
        [
            ApiKeyRecord(
                key="http-key",
                principal=Principal(id="usr_http", scopes=["demo:read"]),
            )
        ]
    )
    defaults = dict(
        registry=create_registry(action),
        auth=auth,
        base_url="http://testserver",
        allowed_hosts=["testserver"],
        allowed_origins=["http://testserver"],
    )
    defaults.update(options)
    return create_server(**defaults)


def test_health_is_unauthenticated() -> None:
    app = make_server().streamable_http_app()
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["tools"] == 1
        assert response.json()["version"] == "0.1.0"


def test_protected_resource_metadata() -> None:
    app = make_server(
        authorization_servers=["https://issuer.example.com"],
        scopes_supported=["demo:read"],
    ).streamable_http_app()
    with TestClient(app) as client:
        response = client.get("/.well-known/oauth-protected-resource")
        assert response.status_code == 200
        document = response.json()
        assert document["resource"] == "http://testserver/mcp"
        assert document["authorization_servers"] == ["https://issuer.example.com"]
        assert document["scopes_supported"] == ["demo:read"]


def test_protected_resource_metadata_is_404_without_base_url() -> None:
    app = make_server(base_url=None).streamable_http_app()
    with TestClient(app) as client:
        assert client.get("/.well-known/oauth-protected-resource").status_code == 404


def test_mcp_requires_authentication() -> None:
    app = make_server().streamable_http_app()
    with TestClient(app) as client:
        response = client.get("/mcp", headers={"Accept": "text/event-stream"})
        assert response.status_code == 401
        assert "Bearer" in response.headers["www-authenticate"]
        assert "resource_metadata" in response.headers["www-authenticate"]
        assert response.json()["error"] == "unauthorized"


def test_mcp_accepts_a_valid_key() -> None:
    app = make_server().streamable_http_app()
    with TestClient(app) as client:
        # A bare GET is not a valid Streamable HTTP request, but reaching the
        # SDK's 400 proves the auth middleware let the request through.
        response = client.get(
            "/mcp",
            headers={
                "Accept": "text/event-stream",
                "Authorization": "Bearer http-key",
            },
        )
        assert response.status_code == 400
        assert "session" in response.text.lower()


def test_x_api_key_is_accepted() -> None:
    app = make_server().streamable_http_app()
    with TestClient(app) as client:
        response = client.get(
            "/mcp",
            headers={
                "Accept": "text/event-stream",
                "X-API-Key": "http-key",
            },
        )
        assert response.status_code == 400
        assert "session" in response.text.lower()


def test_cors_options_are_allowed_without_auth() -> None:
    app = make_server(cors_origins=["https://app.example.com"]).streamable_http_app()
    with TestClient(app) as client:
        response = client.options(
            "/mcp",
            headers={
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status_code == 200
        assert (
            response.headers["access-control-allow-origin"] == "https://app.example.com"
        )


def test_streamable_http_app_is_cached() -> None:
    server = make_server()
    assert server.streamable_http_app() is server.app()
