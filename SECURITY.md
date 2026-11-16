# Security policy

This server gives an AI assistant access to a mailbox, so security reports are
welcome and taken seriously.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead:
the repository's **Security** tab → **Report a vulnerability**.

Include what an attacker can do, the steps to reproduce, and the version or
commit. You should get a first answer within a week.

## In scope

- Reading or sending mail without the user's approval (including through
  instructions hidden in an email).
- Bypassing the OAuth login, the lockout or the token checks of the remote server.
- Reaching Bridge on a non-loopback address, or leaking Bridge credentials.
- Header injection or recipient smuggling in `send_email`.

## Out of scope

- Vulnerabilities in Proton Mail Bridge, the MCP SDK or the MCP clients themselves
  (report them to their maintainers).
- A model following instructions from an email when the user approved the
  resulting action: approval prompts are the defence there, keep them on.
