"""Single-user OAuth 2.1 authorization server for the MCP endpoint.

claude.ai registers itself through dynamic client registration, then sends the
user to /authorize. We redirect to a small password page; once the password
matches MCP_PASSWORD we issue an authorization code. Clients and tokens live in
SQLite so the connector survives container restarts.

Adapted from bring-mcp. Differences: scope "mail", and a global lockout after
repeated wrong passwords (single-user server, so locking everyone out is fine).
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

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
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

log = logging.getLogger("proton-mcp.auth")


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
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
    def __init__(self, store: Store, password: str, public_url: str):
        if len(password) < MIN_PASSWORD_LENGTH:
            raise SystemExit(f"MCP_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters")
        self.store = store
        self.password = password
        self.failures: list[float] = []
        self.public_url = public_url.rstrip("/")
        self.pending: dict[str, tuple[float, str, AuthorizationParams]] = {}

    # Client registration

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self.store.get("client", client_id)
        return OAuthClientInformationFull.model_validate(data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.store.put("client", client_info.client_id, client_info.model_dump(mode="json"))

    # Authorization: hand off to the password page

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        now = time.time()
        self.pending = {k: v for k, v in self.pending.items() if v[0] > now}
        request_id = secrets.token_urlsafe(24)
        self.pending[request_id] = (now + PENDING_TTL, client.client_id, params)
        return f"{self.public_url}/login?req={request_id}"

    async def login_page(self, request: Request) -> Response:
        if request.method == "GET":
            request_id = request.query_params.get("req", "")
            if request_id not in self.pending:
                return HTMLResponse(_page("Request expired, start the connection again from Claude."), status_code=400)
            return HTMLResponse(_page(form_request_id=request_id))

        form = await request.form()
        request_id = str(form.get("req", ""))
        entry = self.pending.get(request_id)
        if not entry or entry[0] < time.time():
            return HTMLResponse(_page("Request expired, start the connection again from Claude."), status_code=400)
        now = time.time()
        self.failures = [t for t in self.failures if t > now - FAILURE_WINDOW]
        client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "?")
        if len(self.failures) >= MAX_FAILURES:
            log.warning("login locked, attempt from %s", client_ip)
            return HTMLResponse(
                _page("Too many attempts. Try again in 15 minutes."), status_code=429
            )
        if not hmac.compare_digest(str(form.get("password", "")).encode(), self.password.encode()):
            self.failures.append(now)
            log.warning("wrong password from %s (%d/%d)", client_ip, len(self.failures), MAX_FAILURES)
            await asyncio.sleep(2)
            return HTMLResponse(_page("Wrong password.", form_request_id=request_id), status_code=401)

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
        return RedirectResponse(
            construct_redirect_uri(str(params.redirect_uri), code=code.code, state=params.state), status_code=302
        )

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


def _page(message: str = "", form_request_id: str | None = None) -> str:
    form = ""
    if form_request_id:
        form = f"""<form method="post" action="login">
  <input type="hidden" name="req" value="{html.escape(form_request_id)}">
  <input type="password" name="password" placeholder="Password" autofocus required>
  <button type="submit">Authorize Claude</button>
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
@media (prefers-color-scheme: dark) {{ body {{ background: #1b1b1b; color: #eee; }} main {{ background: #262626; }} }}
</style></head>
<body><main><h1>Proton Mail MCP</h1><p>{html.escape(message)}</p>{form}</main></body></html>"""
