"""Public Proton Mail MCP server: streamable HTTP + OAuth, for claude.ai connectors.

Reuses the tools from proton_mcp.py unchanged. Differences from the local stdio server:
- every request needs an OAuth token (password page, see auth.py);
- send_email is only registered when ENABLE_SEND=true;
- every tool call is logged (tool name and arguments, never the email body).
"""

import functools
import ipaddress
import logging
import os
import time
from pathlib import Path

import uvicorn
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

import proton_mcp as core
from auth import DEFAULT_REDIRECT_URIS, SCOPE, PasswordOAuthProvider, Store

# The mcp library configures the root logger first, so ours get their own handler.
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
_root = logging.getLogger("proton-mcp")
_root.addHandler(_handler)
_root.setLevel(logging.INFO)
_root.propagate = False
audit = logging.getLogger("proton-mcp.audit")

PUBLIC_URL = os.environ["PUBLIC_URL"].rstrip("/")
ENABLE_SEND = os.environ.get("ENABLE_SEND", "false").strip().lower() in ("1", "true", "yes")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8766"))
ALLOWED_REDIRECT_URIS = os.environ.get("ALLOWED_REDIRECT_URIS", ",".join(DEFAULT_REDIRECT_URIS)).split(",")


def _check_listen_host(host: str) -> None:
    """The server speaks plain HTTP: it must sit behind a TLS reverse proxy on the same machine."""
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback and os.environ.get("ALLOW_NON_LOOPBACK_LISTEN", "").lower() not in ("1", "true", "yes"):
        raise SystemExit(
            f"LISTEN_HOST={host!r} is not a loopback address. The server speaks plain HTTP; keep it on "
            "127.0.0.1 behind a reverse proxy, or set ALLOW_NON_LOOPBACK_LISTEN=true if a private "
            "container network isolates it."
        )


_check_listen_host(LISTEN_HOST)
store = Store(DATA_DIR / "proton-mcp.sqlite")
provider = PasswordOAuthProvider(store, os.environ["MCP_PASSWORD"], PUBLIC_URL, ALLOWED_REDIRECT_URIS)

mcp = MCPServer(
    name="proton-mail",
    title="Proton Mail",
    instructions=core.INSTRUCTIONS,
    auth_server_provider=provider,
    auth=AuthSettings(
        issuer_url=PUBLIC_URL,
        resource_server_url=f"{PUBLIC_URL}/mcp",
        validate_token_resource=False,
        required_scopes=[SCOPE],
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
        ),
        revocation_options=RevocationOptions(enabled=True),
    ),
)


def audited(fn):
    """Log each call: tool name, arguments (without the body), duration, outcome."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        shown = {k: v for k, v in kwargs.items() if k != "body"}
        start = time.monotonic()
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            audit.warning("tool=%s args=%s error=%r", fn.__name__, shown, str(exc)[:200])
            raise
        audit.info("tool=%s args=%s ok %.1fs", fn.__name__, shown, time.monotonic() - start)
        return result

    return wrapper


for _fn in (core.list_folders, core.list_emails, core.search_emails, core.read_email):
    mcp.tool(annotations=core.READ_ONLY)(audited(_fn))
if ENABLE_SEND:
    mcp.tool(annotations=core.SENDS_MAIL)(audited(core.send_email))


@mcp.custom_route("/login", methods=["GET", "POST"])
async def login(request: Request):
    return await provider.login_page(request)


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request):
    return JSONResponse({"status": "ok"})


def main() -> None:
    public_host = PUBLIC_URL.split("://", 1)[1]
    app = mcp.streamable_http_app(
        host=LISTEN_HOST,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[public_host, "localhost:*", "127.0.0.1:*"],
            allowed_origins=[PUBLIC_URL, "https://claude.ai", "http://localhost:*", "http://127.0.0.1:*"],
        ),
    )
    audit.info("starting on %s:%d, public %s, send %s", LISTEN_HOST, PORT, PUBLIC_URL,
               "ENABLED" if ENABLE_SEND else "disabled")
    uvicorn.run(app, host=LISTEN_HOST, port=PORT, proxy_headers=True, forwarded_allow_ips="127.0.0.1")


if __name__ == "__main__":
    main()
