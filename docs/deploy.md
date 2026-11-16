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
- `send_email` is **not exposed** unless `ENABLE_SEND=true`.
- Each tool call is logged (tool and arguments, never the email body):
  `docker logs proton-mcp`.

Read [Security](../README.md#security) before exposing your mailbox.

## 1. DNS

Create an `A` (and/or `AAAA`) record for your chosen name, e.g.
`mcp.example.com`, pointing to the host. Pick a name that isn't already used by
your mail provider (`mail.` often is).

## 2. Proton Mail Bridge (headless)

Bridge requires a paid Proton plan. Download the Linux package from the official
page, https://proton.me/mail/bridge, then:

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
The password page opens: type `MCP_PASSWORD`. The four read tools appear.

## Enable sending

Set `ENABLE_SEND=true` in `.env`, then `docker compose up -d`. In claude.ai, keep
`send_email` on "needs approval" in the connector's tool permissions.

## Hardening checklist

- Automatic security updates: `sudo apt install unattended-upgrades`.
- SSH with keys only: `PasswordAuthentication no` in `/etc/ssh/sshd_config`.
- Docker publishes ports past host firewalls such as ufw. Make sure nothing else
  on the host exposes services you didn't mean to (`ss -tlnp`, and a port scan
  from outside).
- Look at the logs now and then: `docker logs proton-mcp | grep proton-mcp`.
  An unknown `login ok` or a burst of `wrong password` deserves attention.

## Revoke access

- Stop everything: `docker compose down`.
- Revoke all claude.ai tokens: delete `data/proton-mcp.sqlite`, then restart.
- Cut mailbox access entirely: `protonmail-bridge --cli` → `logout`, or revoke
  the Bridge session in Proton → Settings → Security.
