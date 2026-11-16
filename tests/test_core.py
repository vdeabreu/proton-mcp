"""Offline tests for proton_mcp.py: no Bridge, no network."""

import email
import email.policy
import re

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import proton_mcp as p

SENDER = "me@proton.me"


def _original(body="Hello,\n\nSee you tomorrow.", html=None):
    msg = email.message.EmailMessage()
    msg["From"] = "Alice Martin <alice@example.com>"
    msg["To"] = SENDER
    msg["Subject"] = "Plans"
    msg["Date"] = "Mon, 09 Nov 2026 11:13:19 +0000"
    msg["Message-ID"] = "<parent@example.com>"
    msg["References"] = "<root@example.com>"
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    return email.message_from_bytes(msg.as_bytes(), policy=email.policy.default)


# --- folder names ---

@pytest.mark.parametrize("name", ["INBOX", "Éléments envoyés", "Tom & Jerry", "日本語", "Archive/2026 ✓"])
def test_mutf7_roundtrip(name):
    assert p._decode_mutf7(p._encode_mutf7(name)) == name


def test_mutf7_known_values():
    assert p._encode_mutf7("&") == "&-"
    assert p._encode_mutf7("Envoyés") == "Envoy&AOk-s"
    assert p._quote('a"b') == '"a\\"b"'


# --- safety checks ---

@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_loopback_accepted(host):
    p._ensure_loopback(host)


@pytest.mark.parametrize("host", ["10.0.0.1", "192.168.1.2", "example.com", "0.0.0.0", ""])
def test_non_loopback_rejected(host):
    with pytest.raises(ToolError):
        p._ensure_loopback(host)


def test_addresses():
    assert p._addresses("to", "A <a@b.fr>, c@d.com") == ["a@b.fr", "c@d.com"]
    assert p._addresses("cc", None) == []
    for bad in ("not-an-address", "a@b", "a@@b.fr"):
        with pytest.raises(ToolError):
            p._addresses("to", bad)


# --- building messages ---

def test_message_is_html_with_plain_alternative():
    msg, rcpt = p._build_message(SENDER, "a@b.fr", "Hi", "Hello **there**", None, None, None)
    assert msg.get_content_type() == "multipart/alternative"
    assert [part.get_content_type() for part in msg.iter_parts()] == ["text/plain", "text/html"]
    assert "Hello there" in msg.get_body(("plain",)).get_content()
    assert "<strong>there</strong>" in msg.get_body(("html",)).get_content()
    assert rcpt == ["a@b.fr"]


def test_bcc_only_in_envelope():
    msg, rcpt = p._build_message(SENDER, "a@b.fr", "Hi", "x", "c@d.fr", "secret@e.fr", None)
    assert rcpt == ["a@b.fr", "c@d.fr", "secret@e.fr"]
    assert "Bcc" not in msg
    assert "secret@e.fr" not in msg.as_string()


def test_header_injection_rejected():
    with pytest.raises(ToolError):
        p._build_message(SENDER, "a@b.fr", "Hi\r\nBcc: evil@x.com", "x", None, None, None)


def test_reply_threading_and_quote():
    msg, _ = p._build_message(SENDER, "alice@example.com", "Re: Plans", "Sure.", None, None, _original(), True)
    assert msg["In-Reply-To"] == "<parent@example.com>"
    assert msg["References"] == "<root@example.com> <parent@example.com>"
    plain = msg.get_body(("plain",)).get_content()
    assert plain.startswith("Sure.")
    assert "Alice Martin <alice@example.com> wrote:" in plain
    assert "> See you tomorrow." in plain
    html = msg.get_body(("html",)).get_content()
    assert "<blockquote" in html and "See you tomorrow." in html
    assert html.index("Sure.") < html.index("<blockquote")


def test_reply_without_quote():
    msg, _ = p._build_message(SENDER, "a@b.fr", "Re: Plans", "Sure.", None, None, _original(), False)
    assert msg["In-Reply-To"] == "<parent@example.com>"
    assert "See you tomorrow" not in msg.as_string()


def test_quoted_original_is_escaped():
    original = _original(body="<script>alert(1)</script> & co")
    msg, _ = p._build_message(SENDER, "a@b.fr", "Re", "ok", None, None, original, True)
    html = msg.get_body(("html",)).get_content()
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_attribution_languages():
    original = _original()
    en = p._attribution(original, "en")
    fr = p._attribution(original, "fr")
    assert re.fullmatch(r"On \w{3}, \w{3} \d{1,2}, 2026 at \d\d:\d\d, Alice Martin <alice@example.com> wrote:", en)
    assert re.fullmatch(r"Le \S+ \d{1,2} \S+ 2026 à \d\d:\d\d, Alice Martin <alice@example.com> a écrit :", fr)


def test_attribution_without_date():
    original = _original()
    del original["Date"]
    assert p._attribution(original, "en") == "Alice Martin <alice@example.com> wrote:"


# --- Markdown rendering ---

def test_markdown_paragraphs_and_breaks():
    html = p._markdown_to_html("Line one\nline two\n\nSecond paragraph")
    assert html.count("<p ") == 2
    assert "Line one<br>line two" in html


def test_markdown_lists_after_intro():
    html = p._markdown_to_html("Recap:\n- first\n- second\n\n1. one\n2. two")
    assert re.search(r"<p [^>]*>Recap:</p><ul[^>]*><li>first</li><li>second</li></ul>", html)
    assert re.search(r"<ol[^>]*><li>one</li><li>two</li></ol>", html)


def test_markdown_links_and_escaping():
    html = p._markdown_to_html("See [the docs](https://example.com/a?b=1&c=2) or https://x.org/p. <b>&")
    assert '<a href="https://example.com/a?b=1&amp;c=2"' in html and ">the docs</a>" in html
    assert '<a href="https://x.org/p"' in html  # trailing dot not part of the URL
    assert "&lt;b&gt;&amp;" in html


def test_markdown_rejects_javascript_links():
    html = p._markdown_to_html("[click](javascript:alert(1))")
    assert "<a " not in html


def test_markdown_to_plain():
    plain = p._markdown_to_plain("**Bold** and *it* and [docs](https://example.com) and [me](mailto:a@b.fr)")
    assert plain == "Bold and it and docs (https://example.com) and me (a@b.fr)"


def test_markdown_keeps_multiplication_stars():
    assert p._markdown_to_plain("2 * 3 * 4") == "2 * 3 * 4"


# --- reading ---

def test_body_text_prefers_plain_and_converts_html():
    assert p._body_text(_original(body="plain text")) == "plain text"
    msg = email.message.EmailMessage()
    msg.set_content("<p>Hello</p><script>x()</script><p>World</p>", subtype="html")
    text = p._body_text(email.message_from_bytes(msg.as_bytes(), policy=email.policy.default))
    assert "Hello" in text and "World" in text and "x()" not in text


def test_imap_date():
    assert p._imap_date("2026-11-09") == "09-Nov-2026"


# --- sender display name ---

def test_from_header_with_display_name():
    msg, _ = p._build_message(SENDER, "a@b.fr", "Hi", "x", None, None, None, sender_name="Hélène D'Arc")
    raw = msg.as_bytes()
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    assert parsed["From"].addresses[0].display_name == "Hélène D'Arc"
    assert parsed["From"].addresses[0].addr_spec == SENDER


def test_from_header_without_name_is_bare_address():
    msg, _ = p._build_message(SENDER, "a@b.fr", "Hi", "x", None, None, None)
    assert str(msg["From"]) == SENDER


def test_pick_sender_name_prefers_own_address():
    headers = [
        "Victor Pro <victor@work.fr>", "Victor Pro <victor@work.fr>", "Victor Pro <victor@work.fr>",
        f"Victor De Abreu <{SENDER.upper()}>", SENDER,
    ]
    assert p._pick_sender_name(headers, SENDER) == "Victor De Abreu"


def test_pick_sender_name_falls_back_to_other_addresses():
    assert p._pick_sender_name([SENDER, "Jane Doe <jane@alias.me>"], SENDER) == "Jane Doe"
    assert p._pick_sender_name([SENDER, "x@y.fr"], SENDER) is None


@pytest.mark.parametrize("bad", ["", "   ", "a\r\nBcc: x@y.fr", "evil@attacker.com", "x" * 101])
def test_invalid_names_ignored(bad):
    assert p._valid_name(bad) is None


def test_sender_name_from_env(monkeypatch):
    monkeypatch.setenv("PROTON_SENDER_NAME", " Jane Doe ")
    assert p._sender_name(SENDER) == "Jane Doe"
    monkeypatch.setenv("PROTON_SENDER_NAME", "")
    assert p._sender_name(SENDER) is None


def test_sender_name_lookup_failure_does_not_block(monkeypatch):
    monkeypatch.delenv("PROTON_SENDER_NAME", raising=False)
    monkeypatch.setattr(p, "_sent_from_cache", [])

    def boom():
        raise ToolError("Bridge down")

    monkeypatch.setattr(p, "_imap", boom)
    assert p._sender_name(SENDER) is None
    assert p._sent_from_cache == []  # not cached: retried next time


# --- sender addresses ---

ALIAS = "me@alias.org"


@pytest.fixture
def sent(monkeypatch):
    """Pretend the Sent folder holds these From headers."""
    headers = [f"Me <{ALIAS}>", f"Me <{ALIAS}>", "Me <me@third.net>", SENDER]
    monkeypatch.setattr(p, "_sent_from_headers", lambda: headers)
    monkeypatch.delenv("PROTON_FROM_ADDRESSES", raising=False)
    monkeypatch.delenv("PROTON_SENDER_NAME", raising=False)
    return headers


def test_sender_addresses_login_first_then_by_use(sent):
    assert p._sender_addresses(SENDER.upper()) == [SENDER, ALIAS, "me@third.net"]


def test_sender_addresses_from_env(sent, monkeypatch):
    monkeypatch.setenv("PROTON_FROM_ADDRESSES", "New <new@x.fr>, " + ALIAS)
    assert p._sender_addresses(SENDER) == [SENDER, "new@x.fr", ALIAS, "me@third.net"]


def test_choose_sender_accepts_own_address(sent):
    assert p._choose_sender(SENDER, f"Me <{ALIAS.upper()}>", None) == ALIAS


@pytest.mark.parametrize("bad", ["evil@attacker.com", "not an address", f"{ALIAS}\r\nBcc: x@y.fr"])
def test_choose_sender_refuses_other_addresses(sent, bad):
    with pytest.raises(ToolError):
        p._choose_sender(SENDER, bad, None)


def test_choose_sender_defaults_to_login(sent):
    assert p._choose_sender(SENDER, None, None) == SENDER


def test_reply_goes_out_from_the_address_that_received_it(sent):
    original = _original()
    original.replace_header("To", f"Someone <x@y.fr>, Me <{ALIAS}>")
    assert p._choose_sender(SENDER, None, original) == ALIAS


def test_reply_to_unknown_address_falls_back_to_login(sent):
    original = _original()
    original.replace_header("To", "list@lists.example.org")
    assert p._choose_sender(SENDER, None, original) == SENDER


def test_explicit_from_address_wins_over_reply_default(sent):
    original = _original()
    original.replace_header("To", ALIAS)
    assert p._choose_sender(SENDER, SENDER, original) == SENDER


def test_list_sender_addresses(sent, monkeypatch):
    monkeypatch.setenv("PROTON_BRIDGE_USER", SENDER)
    monkeypatch.setenv("PROTON_BRIDGE_PASSWORD", "p")
    rows = p.list_sender_addresses()
    assert [r["address"] for r in rows] == [SENDER, ALIAS, "me@third.net"]
    assert rows[0]["default"] and not rows[1]["default"]
    assert rows[1]["name"] == "Me"


def test_message_id_uses_the_chosen_address_domain():
    msg, _ = p._build_message(ALIAS, "a@b.fr", "Hi", "x", None, None, None, sender_name="Me")
    assert msg["Message-ID"].endswith("@alias.org>")
    assert msg["From"].addresses[0].addr_spec == ALIAS
