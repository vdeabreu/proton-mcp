# Remote deployment (claude.ai connector)

This guide runs the server on a Linux host so you can add it as a custom
connector in claude.ai (web and mobile). It was written for Debian 13 with
Docker, but any Linux with Docker and a reverse proxy works.

```
claude.ai ──HTTPS──> reverse proxy :443 (mcp.example.com) ──> 127.0.0.1:8766 proton-mcp (Docker, host network)
                                                                    └──> 127.0.0.1:1143/1025 Proton Mail Bridge (systemd user service)
```

- Only the reverse proxy is reachable from the internet. Bridge and the MCP
  server listen on 127.0.0.1.
- Each claude.ai connection goes through an OAuth password page (`MCP_PASSWORD`).
  After 5 wrong passwords in 15 minutes, login is locked for 15 minutes.
- `/mcp` only accepts Anthropic's outbound IP ranges (reverse proxy rule).
- `send_email` (and `list_sender_addresses`) are **not exposed** unless `ENABLE_SEND=true`.
- Each tool call is logged (tool and arguments, never the email body):
  `docker logs proton-mcp`.

Read [Security](../README.md#security) before exposing your mailbox.

## 1. DNS

Create an `A` (and/or `AAAA`) record for your chosen name, e.g.
`mcp.example.com`, pointing to the host. Pick a name that isn't already used by
your mail provider (`mail.` often is).

## 2. Proton Mail Bridge (headless)

Bridge requires a paid Proton plan. Download the Linux package from the official
page, https://proton.me/mail/bridge.

**Verify the package before installing it.** Unlike Windows and macOS, Linux
packages aren't checked automatically: follow Proton's guide,
https://proton.me/support/verifying-bridge-package (`debsig-verify` for the
.deb, `rpm --checksig` for the .rpm). Don't install a package that fails the check.

Then:

```bash
sudo apt install ./protonmail-bridge_*_amd64.deb pass
# Keyring for Bridge: a GPG key without passphrase, so the service starts unattended
gpg --batch --passphrase '' --quick-gen-key 'Proton Bridge' default default never
pass init 'Proton Bridge'
# Log in (Proton password + 2FA)
protonmail-bridge --cli
#   > login
#   > info        <- Bridge username/password for .env (NOT your Proton password)
#   > exit
```

If Bridge says *"not able to detect a supported password manager"*, `pass` isn't
initialized yet: exit, run the `gpg` and `pass init` lines, delete
`~/.config/protonmail/bridge-v3/insecure` (unencrypted vault created on the
failed start, only if no account is logged in yet), and start again.

**About the passphrase-less key.** Bridge stores its vault key in `pass`, which
encrypts it with this GPG key. Without a passphrase, the service can start at
boot with nobody to type it, but anyone who gets a shell as this user (or root)
can read the vault and use your mailbox. To narrow that, run Bridge under a
dedicated account with no SSH login, and keep that account out of the `docker`
group (membership in `docker` is equivalent to root).

Run Bridge as a user service that starts at boot:

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/protonmail-bridge.service <<'EOF'
[Unit]
Description=Proton Mail Bridge
After=network-online.target

[Service]
ExecStart=/usr/bin/protonmail-bridge --noninteractive
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF
sudo loginctl enable-linger "$USER"
systemctl --user daemon-reload
systemctl --user enable --now protonmail-bridge
ss -tln | grep -E '1143|1025'   # must show 127.0.0.1 only
```

## 3. MCP server

```bash
git clone https://github.com/vdeabreu/proton-mcp && cd proton-mcp
cp .env.example .env && chmod 600 .env
mkdir -p data && chmod 700 data
openssl rand -base64 30          # -> MCP_PASSWORD
nano .env                        # Bridge user/password from `info`, MCP_PASSWORD, PUBLIC_URL
docker compose up -d --build
docker logs proton-mcp           # "starting on 127.0.0.1:8766 ... send disabled"
curl -s http://127.0.0.1:8766/health
```

The container runs as uid 1000; if your user has another uid, `chown 1000 data`.

The container uses the host network because Bridge only listens on the host's
127.0.0.1. The side effect: if the server were compromised, it could also reach
every other service listening on the host's loopback. Don't run other sensitive
local-only services on the same machine, or put them behind their own
authentication.

## 4. Reverse proxy + certificate

Pick one, and replace `mcp.example.com` with your domain:

- **Apache**: [`deploy/apache/proton-mcp.conf`](../deploy/apache/proton-mcp.conf)
  (steps at the top of the file, certificate with certbot).
- **Caddy**: [`deploy/caddy/Caddyfile`](../deploy/caddy/Caddyfile)
  (certificate is automatic).

Both restrict `/mcp` to Anthropic's outbound ranges. Check them:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://mcp.example.com/mcp   # 403 from your machine
curl -s https://mcp.example.com/.well-known/oauth-protected-resource/mcp        # JSON, open
```

## 5. claude.ai

Settings → Connectors → Add custom connector → `https://mcp.example.com/mcp`.
The password page opens, saying that **Claude** asks for access and that the
authorization goes to **claude.ai**. Type `MCP_PASSWORD`. The four read tools
appear.

Only type the password on a page you opened by clicking *Connect* yourself: an
authorization link someone sends you would connect *their* account.

## Enable sending

Set `ENABLE_SEND=true` in `.env`, then `docker compose up -d`. In claude.ai, keep
`send_email` on "needs approval" in the connector's tool permissions. Start a new
conversation (or reconnect the connector) for the new tools to show up.

Mail goes out from the Bridge login by default; `list_sender_addresses` shows the
other addresses you can send from. An address you've never sent from isn't found
automatically: add it to `PROTON_FROM_ADDRESSES` in `.env`.

## Hardening checklist

- Automatic security updates: `sudo apt install unattended-upgrades`.
- SSH with keys only: `PasswordAuthentication no` in `/etc/ssh/sshd_config`.
- Docker publishes ports past host firewalls such as ufw. Make sure nothing else
  on the host exposes services you didn't mean to (`ss -tlnp`, and a port scan
  from outside).
- Look at the logs now and then: `docker logs proton-mcp | grep proton-mcp`.
  An unknown `login ok`, a burst of `wrong password` or `registration refused`
  deserves attention.
- If login says *"Too many attempts"* although you typed nothing wrong, someone
  is failing on purpose to lock you out. Wait 15 minutes, or restart the
  container (`docker compose restart`) to reset the counter. Existing claude.ai
  sessions are not affected.

## Revoke access

- Stop everything: `docker compose down`.
- Revoke all claude.ai tokens: `docker compose down`, delete `data/proton-mcp.sqlite`,
  then `docker compose up -d` (and reconnect the connector).
- Cut mailbox access entirely: `protonmail-bridge --cli` → `logout`, or revoke
  the Bridge session in Proton → Settings → Security.
