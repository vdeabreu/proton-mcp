"""Single-user OAuth 2.1 authorization server for the MCP endpoint.

claude.ai registers itself through dynamic client registration, then sends the
user to /authorize. We redirect to a small password page; once the password
matches MCP_PASSWORD we issue an authorization code. Clients and tokens live in
SQLite so the connector survives container restarts.

Hardening:
- only redirect URIs from ALLOWED_REDIRECT_URIS (claude.ai's callback by default)
  can be registered, and the number of stored clients is capped;
- the password page shows which client is asking and where the code will go,
  and can't be framed by another site;
- a global lockout after repeated wrong passwords. It's a single-user server, so
  locking everyone out is acceptable: tokens already issued keep working, only
  new logins wait.

Known limit: someone who adds *your* server URL as a connector in *their own*
claude.ai account gets a genuine claude.ai authorization link. If you open it
and type your password, their account gets access. Only type the password right
after clicking "Connect" yourself.
"""

import asyncio
import hmac
import html
import json
import logging
import secrets
import sqlite3
import time
from pathlib import Path

from urllib.parse import urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

ACCESS_TTL = 3600
REFRESH_TTL = 90 * 24 * 3600
CODE_TTL = 300
PENDING_TTL = 600
SCOPE = "mail"
MAX_FAILURES = 5          # wrong passwords allowed...
FAILURE_WINDOW = 15 * 60  # ...within this many seconds, then login is locked for the same duration
MIN_PASSWORD_LENGTH = 20
MAX_CLIENTS = 20          # registered OAuth clients kept; oldest unused ones are evicted
MAX_PENDING = 50          # login requests waiting for the password
DEFAULT_REDIRECT_URIS = ("https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback")

# The password page needs no script, no external resource, and must not be framed.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

log = logging.getLogger("proton-mcp.auth")


class Store:
    def __init__(self, path: Path):
        # OAuth tokens live here: owner-only directory and file, whatever the umask.
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.touch(mode=0o600, exist_ok=True)
        path.chmod(0o600)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS kv (kind TEXT, key TEXT, value TEXT, PRIMARY KEY (kind, key))")
        self.db.commit()

    def get(self, kind: str, key: str) -> dict | None:
        row = self.db.execute("SELECT value FROM kv WHERE kind = ? AND key = ?", (kind, key)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, kind: str, key: str, value: dict) -> None:
        self.db.execute("REPLACE INTO kv VALUES (?, ?, ?)", (kind, key, json.dumps(value)))
        self.db.commit()

    def delete(self, kind: str, key: str) -> None:
        self.db.execute("DELETE FROM kv WHERE kind = ? AND key = ?", (kind, key))
        self.db.commit()

    def purge_expired(self) -> None:
        now = time.time()
        for kind, key, value in self.db.execute("SELECT kind, key, value FROM kv WHERE kind != 'client'").fetchall():
            expires_at = json.loads(value).get("expires_at")
            if expires_at and expires_at < now:
                self.delete(kind, key)


class PasswordOAuthProvider:
    def __init__(
        self, store: Store, password: str, public_url: str,
        allowed_redirect_uris: tuple[str, ...] | list[str] = DEFAULT_REDIRECT_URIS,
    ):
        if len(password) < MIN_PASSWORD_LENGTH:
            raise SystemExit(f"MCP_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters")
        self.store = store
        self.password = password
        self.failures: list[float] = []
        self.public_url = public_url.rstrip("/")
        self.allowed_redirect_uris = {u.strip() for u in allowed_redirect_uris if u.strip()}
        self.pending: dict[str, tuple[float, str, AuthorizationParams]] = {}

    # Client registration

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self.store.get("client", client_id)
        return OAuthClientInformationFull.model_validate(data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in client_info.redirect_uris or []]
        refused = [u for u in uris if u not in self.allowed_redirect_uris]
        if not uris or refused:
            log.warning("registration refused, redirect_uris=%s", uris)
            raise RegistrationError("invalid_redirect_uri", "redirect_uri not allowed by this server")
        self._make_room_for_client()
        self.store.put("client", client_info.client_id, client_info.model_dump(mode="json"))
        log.info("client registered: %s (%s)", client_info.client_name, client_info.client_id)

    def _make_room_for_client(self) -> None:
        """Keep at most MAX_CLIENTS clients: evict the oldest ones that hold no token."""
        rows = self.store.db.execute("SELECT key, value FROM kv WHERE kind = 'client'").fetchall()
        if len(rows) < MAX_CLIENTS:
            return
        in_use = {
            json.loads(v)["client_id"]
            for (v,) in self.store.db.execute("SELECT value FROM kv WHERE kind IN ('access', 'refresh')")
        }
        idle = sorted(
            (json.loads(v).get("client_id_issued_at") or 0, k) for k, v in rows if k not in in_use
        )
        for _, client_id in idle[: len(rows) - MAX_CLIENTS + 1]:
            self.store.delete("client", client_id)
        if len(rows) - len(idle) >= MAX_CLIENTS:
            raise RegistrationError("invalid_client_metadata", "too many active clients, revoke one first")

    # Authorization: hand off to the password page

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        now = time.time()
        self.pending = {k: v for k, v in self.pending.items() if v[0] > now}
        while len(self.pending) >= MAX_PENDING:
            self.pending.pop(next(iter(self.pending)))  # drop the oldest
        request_id = secrets.token_urlsafe(24)
        self.pending[request_id] = (now + PENDING_TTL, client.client_id, params)
        return f"{self.public_url}/login?req={request_id}"

    async def _requester(self, client_id: str, params: AuthorizationParams) -> tuple[str, str]:
        client = await self.get_client(client_id)
        name = (client.client_name if client else None) or "Unknown client"
        return name, urlsplit(str(params.redirect_uri)).netloc

    async def login_page(self, request: Request) -> Response:
        expired = "Request expired, start the connection again from Claude."
        if request.method == "GET":
            request_id = request.query_params.get("req", "")
            entry = self.pending.get(request_id)
            if not entry or entry[0] < time.time():
                return _html(_page(expired), 400)
            return _html(_page(form_request_id=request_id, requester=await self._requester(entry[1], entry[2])))

        form = await request.form()
        request_id = str(form.get("req", ""))
        entry = self.pending.get(request_id)
        if not entry or entry[0] < time.time():
            return _html(_page(expired), 400)
        now = time.time()
        self.failures = [t for t in self.failures if t > now - FAILURE_WINDOW]
        # uvicorn already resolved the client address from the trusted proxy's X-Forwarded-For.
        client_ip = request.client.host if request.client else "?"
        if len(self.failures) >= MAX_FAILURES:
            log.warning("login locked, attempt from %s", client_ip)
            return _html(_page("Too many attempts. Try again in 15 minutes."), 429)
        if not hmac.compare_digest(str(form.get("password", "")).encode(), self.password.encode()):
            self.failures.append(now)
            log.warning("wrong password from %s (%d/%d)", client_ip, len(self.failures), MAX_FAILURES)
            await asyncio.sleep(2)
            requester = await self._requester(entry[1], entry[2])
            return _html(_page("Wrong password.", form_request_id=request_id, requester=requester), 401)

        log.info("login ok from %s, client %s", client_ip, entry[1])
        self.failures.clear()
        del self.pending[request_id]
        _, client_id, params = entry
        code = AuthorizationCode(
            code=secrets.token_urlsafe(32),
            scopes=params.scopes or [SCOPE],
            expires_at=time.time() + CODE_TTL,
            client_id=client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject="owner",
        )
        self.store.put("code", code.code, code.model_dump(mode="json"))
        response = RedirectResponse(
            construct_redirect_uri(str(params.redirect_uri), code=code.code, state=params.state), status_code=302
        )
        response.headers.update({"Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})
        return response

    # Tokens

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        data = self.store.get("code", authorization_code)
        if not data or data["client_id"] != client.client_id:
            return None
        return AuthorizationCode.model_validate(data)

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        self.store.delete("code", authorization_code.code)
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource)

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str):
        data = self.store.get("refresh", refresh_token)
        if not data or data["client_id"] != client.client_id:
            return None
        return RefreshToken.model_validate(data)

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        if scopes and not set(scopes) <= set(refresh_token.scopes):
            raise TokenError("invalid_scope", "requested scopes exceed the original grant")
        self._revoke_pair(refresh_token.token)
        return self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.resource)

    async def load_access_token(self, token: str) -> AccessToken | None:
        data = self.store.get("access", token)
        if not data or data["expires_at"] < time.time():
            return None
        return AccessToken.model_validate(data)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        data = self.store.get("access", token.token)
        self._revoke_pair(data["refresh"] if data else token.token)
        self.store.delete("access", token.token)

    async def exchange_identity_assertion(self, client, params) -> OAuthToken:
        raise TokenError("unsupported_grant_type")

    def _issue(self, client_id: str, scopes: list[str], resource: str | None) -> OAuthToken:
        self.store.purge_expired()
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = int(time.time())
        common = {"client_id": client_id, "scopes": scopes, "resource": resource, "subject": "owner"}
        self.store.put(
            "access", access, {**common, "token": access, "expires_at": now + ACCESS_TTL, "refresh": refresh}
        )
        self.store.put(
            "refresh", refresh, {**common, "token": refresh, "expires_at": now + REFRESH_TTL, "access": access}
        )
        return OAuthToken(
            access_token=access, expires_in=ACCESS_TTL, refresh_token=refresh, scope=" ".join(scopes)
        )

    def _revoke_pair(self, refresh_token: str) -> None:
        data = self.store.get("refresh", refresh_token)
        if data:
            self.store.delete("access", data["access"])
        self.store.delete("refresh", refresh_token)


def _html(content: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(content, status_code=status_code, headers=SECURITY_HEADERS)


def _page(message: str = "", form_request_id: str | None = None, requester: tuple[str, str] | None = None) -> str:
    form = ""
    if form_request_id:
        who = ""
        if requester:
            name, host = (html.escape(x) for x in requester)
            who = f"""<div class="who"><b>{name}</b> asks for access to your mailbox.<br>
The authorization will be sent to <b>{host}</b>.</div>
<div class="warn">Only continue if you just clicked <i>Connect</i> yourself.
If someone sent you this link, close this page.</div>"""
        form = f"""{who}<form method="post" action="login">
  <input type="hidden" name="req" value="{html.escape(form_request_id)}">
  <input type="password" name="password" placeholder="Password" autofocus required>
  <button type="submit">Authorize</button>
</form>"""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proton Mail MCP</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #f4f4f2; color: #222; display: grid;
       place-items: center; min-height: 100vh; margin: 0; padding: 0 16px; }}
main {{ background: #fff; padding: 2rem; border-radius: 12px; max-width: 360px; width: 100%;
       box-shadow: 0 2px 12px #0001; }}
input, button {{ width: 100%; box-sizing: border-box; padding: .7rem; margin-top: .6rem; font-size: 1rem;
                border-radius: 8px; border: 1px solid #ccc; }}
button {{ background: #6d4aff; color: #fff; border: 0; cursor: pointer; }}
p {{ color: #b33; }}
.who {{ margin: .4rem 0 .8rem; line-height: 1.5; }}
.warn {{ font-size: .9rem; padding: .6rem .8rem; border-radius: 8px; background: #fff4d6; color: #5c4400; }}
@media (prefers-color-scheme: dark) {{ body {{ background: #1b1b1b; color: #eee; }} main {{ background: #262626; }}
  .warn {{ background: #3a3020; color: #f3dca0; }} }}
</style></head>
<body><main><h1>Proton Mail MCP</h1><p>{html.escape(message)}</p>{form}</main></body></html>"""
