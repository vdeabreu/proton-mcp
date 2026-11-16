"""OAuth login page of the remote server: password check and lockout."""

import asyncio
import types

import pytest
from mcp.server.auth.provider import AuthorizationParams, RegistrationError
from mcp.shared.auth import OAuthClientInformationFull
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

import auth

PASSWORD = "correct-horse-battery-staple"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    async def no_sleep(_):
        return None

    # Skip the 2 s delay after a wrong password.
    monkeypatch.setattr(auth, "asyncio", types.SimpleNamespace(sleep=no_sleep))
    provider = auth.PasswordOAuthProvider(auth.Store(tmp_path / "db.sqlite"), PASSWORD, "https://mcp.example.com")
    app = Starlette(routes=[Route("/login", provider.login_page, methods=["GET", "POST"])])
    client = TestClient(app, follow_redirects=False)

    def new_request() -> str:
        info = OAuthClientInformationFull(client_id="c1", redirect_uris=[REDIRECT])
        params = AuthorizationParams(
            state="s", scopes=[auth.SCOPE], code_challenge="x" * 43, redirect_uri=REDIRECT,
            redirect_uri_provided_explicitly=True, resource=None,
        )
        url = asyncio.run(provider.authorize(info, params))
        return url.split("req=", 1)[1]

    return provider, client, new_request


def test_short_password_refused(tmp_path):
    with pytest.raises(SystemExit):
        auth.PasswordOAuthProvider(auth.Store(tmp_path / "db.sqlite"), "too-short", "https://x")


def test_login_ok_redirects_with_code(setup):
    provider, client, new_request = setup
    r = client.post("/login", data={"req": new_request(), "password": PASSWORD})
    assert r.status_code == 302
    assert r.headers["location"].startswith(REDIRECT + "?code=")
    assert "state=s" in r.headers["location"]


def test_unknown_request_refused(setup):
    _, client, _ = setup
    assert client.post("/login", data={"req": "nope", "password": PASSWORD}).status_code == 400


def test_request_is_single_use(setup):
    _, client, new_request = setup
    req = new_request()
    assert client.post("/login", data={"req": req, "password": PASSWORD}).status_code == 302
    assert client.post("/login", data={"req": req, "password": PASSWORD}).status_code == 400


def test_lockout_after_five_failures(setup):
    _, client, new_request = setup
    req = new_request()
    codes = [client.post("/login", data={"req": req, "password": "wrong"}).status_code for _ in range(6)]
    assert codes == [401] * 5 + [429]
    # Even the right password is refused while locked.
    assert client.post("/login", data={"req": req, "password": PASSWORD}).status_code == 429


def test_lockout_expires(setup, monkeypatch):
    provider, client, new_request = setup
    req = new_request()
    for _ in range(5):
        client.post("/login", data={"req": req, "password": "wrong"})
    provider.failures = [t - auth.FAILURE_WINDOW - 1 for t in provider.failures]
    assert client.post("/login", data={"req": req, "password": PASSWORD}).status_code == 302


def test_login_page_escapes_request_id(setup):
    _, client, new_request = setup
    r = client.get("/login", params={"req": new_request()})
    assert r.status_code == 200 and "<form" in r.text


# --- registration hardening ---

def _client(client_id: str, redirect: str = REDIRECT, name: str = "Claude", issued_at: int = 0):
    return OAuthClientInformationFull(
        client_id=client_id, redirect_uris=[redirect], client_name=name, client_id_issued_at=issued_at
    )


def test_registration_refuses_unknown_redirect(setup):
    provider, _, _ = setup
    with pytest.raises(RegistrationError) as exc:
        asyncio.run(provider.register_client(_client("evil", "https://attacker.example/cb")))
    assert exc.value.error == "invalid_redirect_uri"
    assert asyncio.run(provider.get_client("evil")) is None


def test_registration_accepts_claude_callback(setup):
    provider, _, _ = setup
    asyncio.run(provider.register_client(_client("ok")))
    assert asyncio.run(provider.get_client("ok")) is not None


def test_custom_redirect_allowlist(tmp_path):
    provider = auth.PasswordOAuthProvider(
        auth.Store(tmp_path / "db.sqlite"), PASSWORD, "https://x", ["http://localhost:6274/oauth/callback"]
    )
    asyncio.run(provider.register_client(_client("inspector", "http://localhost:6274/oauth/callback")))
    with pytest.raises(RegistrationError):
        asyncio.run(provider.register_client(_client("claude")))


def _count_clients(provider) -> int:
    return provider.store.db.execute("SELECT count(*) FROM kv WHERE kind = 'client'").fetchone()[0]


def test_client_count_is_capped_by_evicting_idle_ones(setup):
    provider, _, _ = setup
    for i in range(auth.MAX_CLIENTS + 15):
        asyncio.run(provider.register_client(_client(f"c{i}", issued_at=i)))
    assert _count_clients(provider) == auth.MAX_CLIENTS
    assert asyncio.run(provider.get_client("c0")) is None  # oldest evicted
    assert asyncio.run(provider.get_client(f"c{auth.MAX_CLIENTS + 14}")) is not None


def test_clients_with_tokens_are_never_evicted(setup):
    provider, _, _ = setup
    for i in range(auth.MAX_CLIENTS):
        asyncio.run(provider.register_client(_client(f"c{i}", issued_at=i)))
        provider._issue(f"c{i}", [auth.SCOPE], None)
    with pytest.raises(RegistrationError):
        asyncio.run(provider.register_client(_client("one-too-many", issued_at=999)))
    assert _count_clients(provider) == auth.MAX_CLIENTS


def test_pending_requests_are_capped(setup):
    provider, _, new_request = setup
    for _ in range(auth.MAX_PENDING + 30):
        new_request()
    assert len(provider.pending) == auth.MAX_PENDING


# --- password page ---

def test_page_has_security_headers(setup):
    _, client, new_request = setup
    for r in (client.get("/login", params={"req": new_request()}), client.get("/login", params={"req": "nope"})):
        assert r.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["referrer-policy"] == "no-referrer"
        assert r.headers["cache-control"] == "no-store"


def test_page_shows_requester_escaped(setup):
    provider, client, new_request = setup
    asyncio.run(provider.register_client(_client("c1", name="<script>x</script>Claude")))
    r = client.get("/login", params={"req": new_request()})
    assert "&lt;script&gt;x&lt;/script&gt;Claude" in r.text and "<script>" not in r.text
    assert "<b>claude.ai</b>" in r.text
    assert "clicked <i>Connect</i> yourself" in r.text


def test_page_without_registered_client(setup):
    _, client, new_request = setup
    assert "Unknown client" in client.get("/login", params={"req": new_request()}).text


def test_logs_use_resolved_client_ip_not_raw_header(setup, caplog):
    _, client, new_request = setup
    with caplog.at_level("WARNING", logger="proton-mcp.auth"):
        client.post("/login", data={"req": new_request(), "password": "wrong"},
                    headers={"X-Forwarded-For": "1.2.3.4"})
    assert "1.2.3.4" not in caplog.text
