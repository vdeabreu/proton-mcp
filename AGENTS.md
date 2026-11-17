# AGENTS.md

Notes for coding agents (and humans) working on this repository. The README covers
what the project does and how to set it up; this file covers what to keep in mind
when changing it.

## Layout

- `proton_mcp.py`: all mail logic (IMAP, SMTP, parsing, Markdown, quoting) and the
  local stdio server. Every tool is a plain function, registered on `mcp`.
- `remote/server.py`: HTTP server for claude.ai. Imports `proton_mcp`, wraps the
  tools with an audit log, adds OAuth. `remote/auth.py`: the OAuth provider
  (password page, lockout, SQLite store).
- `Dockerfile` and `compose.yml` at the root, because the image copies files from
  both the root and `remote/`.
- `deploy/`: example reverse-proxy configs. `docs/deploy.md`: the full server guide.

## Commands

```bash
pip install -e ".[remote,dev]"
pytest
ruff check .
docker build -t proton-mcp .
```

Tests need no Bridge and no network: `tests/test_security.py` runs a fake IMAP
server on 127.0.0.1. `server.py` reads its configuration at import time, so
`tests/test_server.py` and the send-flag tests import it in a subprocess. On
Windows the `PYTHONPATH` separator is `;`.

## Releasing

Bump `version` in `pyproject.toml`, commit, then push a tag `vX.Y.Z` with the same
version. `.github/workflows/release.yml` checks the tag matches, runs the tests,
publishes to PyPI (trusted publishing, environment `pypi`), then publishes
`server.json` to the MCP Registry as `io.github.vdeabreu/proton-mcp` (GitHub OIDC). The
registry checks ownership through the `mcp-name:` comment at the top of the
README: keep it.

## Invariants: don't break these

- **Read-only IMAP.** Folders are opened with EXAMINE (`select(readonly=True)`)
  and bodies fetched with `BODY.PEEK`, so nothing is marked read, moved or deleted.
  No tool may write to the mailbox.
- **No control characters reach IMAP.** imaplib sends arguments raw: a CR/LF in a
  search term or folder name ends the command and runs the rest as new IMAP
  commands. Every string that goes into an IMAP command passes through `_clean()`
  (folder names via `_quote()`). Add the same for any new argument.
- **Single-line headers.** `_build_message` rejects line breaks in subject and
  recipients. Bcc goes in the SMTP envelope only, never in the headers.
- **Bridge on loopback only.** Its certificate is self-signed and TLS verification
  is off, so `_ensure_loopback()` must stay.
- **Sending is explicit.** `send_email` keeps `destructiveHint=True`, is registered
  only when sending is enabled (`PROTON_ENABLE_SEND` locally, `ENABLE_SEND`
  remotely, off by default there), and its docstring and `INSTRUCTIONS` tell the
  model to get the user's approval of the exact text first.
- **Only the user's own addresses send.** In combined mode Bridge accepts any
  `MAIL FROM`, so `_choose_sender` checks `from_address` against
  `_sender_addresses()` (Bridge login, `PROTON_FROM_ADDRESSES`, addresses in
  Sent) and refuses anything else.
- **Email content is untrusted.** It can carry prompt injection. `_TextExtractor`
  drops hidden HTML (display:none, font-size:0, `hidden`…); don't add features
  that act on instructions found in a message.
- **Remote hardening.** The HTTP server listens on loopback behind a reverse proxy
  (`_check_listen_host`); OAuth registration only accepts the claude.ai callback
  URLs; the login page sends anti-framing headers. Logs record tool names and
  arguments but never message bodies.
- **Private data directory.** `Store` creates the directory 0700 and the SQLite
  file 0600: it holds OAuth tokens.

## Proton and Bridge behaviour (learned the hard way)

- **Proton rebuilds the MIME message.** What Bridge receives over SMTP is not
  what recipients get: Proton re-encodes every part in base64, uses its own
  boundary, rewrites the HTML head and regenerates the text/plain part from the
  HTML (so a paragraph followed by a list gains a blank line). Changing encodings
  or the plain-text rendering here has no visible effect. Mail sent from Proton's
  web app has the same structure.
- **Bridge doesn't add the display name.** It sends `From` exactly as given, and
  IMAP can't read the display name set in Proton's settings. The server uses
  `PROTON_SENDER_NAME`, else the most frequent name in recent `Sent` messages.
- **One Bridge login covers every address** (combined mode, the default): the
  server can send from any of them by setting `From` and the envelope sender.
  Bridge doesn't check that address at `MAIL FROM` time.
- **Deliverability is outside the server's control.** SPF, DKIM and DMARC are
  handled by Proton for the sender's domain. Messages go out from Proton's shared
  IPs, so IP-based tools (Microsoft SNDS) don't apply.
- **Headless Bridge on Linux** needs a keychain: `pass` with a GPG key. Without
  one Bridge falls back to an "insecure" vault. See `docs/deploy.md`.
- **Folder names** use IMAP modified UTF-7; non-ASCII search terms are sent with
  `CHARSET UTF-8` as a literal.

## Conventions

- Python 3.12+, ruff with line length 120.
- Tool docstrings are what the model reads: keep them accurate and short.
- Add a test with each change, especially for anything touching IMAP arguments,
  headers or HTML parsing.
- Dependencies and the Docker base image are pinned (image by digest, actions by
  SHA). Dependabot opens the update PRs.
