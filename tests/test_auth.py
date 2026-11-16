"""OAuth login page of the remote server: password check and lockout."""

import asyncio
import types

import pytest
from mcp.server.auth.provider import AuthorizationParams
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
