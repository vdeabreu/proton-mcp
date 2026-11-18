"""send_email confirmation modes, through a real MCP client in-process (no Bridge, no network)."""

import contextlib

import anyio
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import ElicitResult

import proton_mcp as p

SENDER = "me@proton.me"
ARGS = {"to": "alex@example.com", "subject": "Thursday", "body": "Hi Alex,\n\nThursday works.\n\nJane"}
PROTOCOLS = ["legacy", "2026-07-28"]  # server-to-client request mid-call / input_required retry rounds


class FakeSMTP:
    sent: list = []

    def send_message(self, msg, from_addr, to_addrs):
        FakeSMTP.sent.append((msg, from_addr, to_addrs))
        return {}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    FakeSMTP.sent = []
    monkeypatch.setattr(p, "_credentials", lambda: (SENDER, "pw"))
    monkeypatch.setattr(p, "_sent_from_headers", lambda: [f"Jane Doe <{SENDER}>"])
    monkeypatch.delenv("PROTON_SENDER_NAME", raising=False)
    monkeypatch.setattr(p, "_smtp", lambda: contextlib.nullcontext(FakeSMTP()))


def _server(confirm):
    server = MCPServer("test", instructions=p.instructions(confirm))
    server.tool(name="send_email", annotations=p.SENDS_MAIL)(p.send_tool(confirm))
    return server


def _call(confirm, mode, answer=None, args=ARGS):
    """Call send_email; `answer(message) -> ElicitResult` plays the user, None = client without elicitation."""
    prompts = []

    async def on_elicit(context, params):
        prompts.append(params.message)
        return answer(params.message)

    async def run():
        kwargs = {"elicitation_callback": on_elicit} if answer else {}
        async with Client(_server(confirm), mode=mode, **kwargs) as client:
            return await client.call_tool("send_email", args)

    return anyio.run(run), prompts


def _text(result):
    return " ".join(getattr(c, "text", "") for c in result.content)


@pytest.mark.parametrize("mode", PROTOCOLS)
def test_elicit_sends_after_user_confirms(mode):
    result, prompts = _call("elicit", mode, lambda m: ElicitResult(action="accept", content={"send": True}))
    assert not result.is_error, _text(result)
    assert len(FakeSMTP.sent) == 1
    assert len(prompts) == 1
    prompt = prompts[0]
    for expected in (f"From: Jane Doe <{SENDER}>", "To: alex@example.com", "Subject: Thursday", "Thursday works."):
        assert expected in prompt


@pytest.mark.parametrize("mode", PROTOCOLS)
@pytest.mark.parametrize("reply", [
    ElicitResult(action="accept", content={"send": False}),
    ElicitResult(action="decline"),
    ElicitResult(action="cancel"),
])
def test_elicit_sends_nothing_without_confirmation(mode, reply):
    result, prompts = _call("elicit", mode, lambda m: reply)
    assert result.is_error
    assert "nothing was sent" in _text(result)
    assert "another way" in _text(result)
    assert prompts and FakeSMTP.sent == []


@pytest.mark.parametrize("mode", PROTOCOLS)
def test_elicit_refuses_clients_that_cannot_ask(mode):
    result, _ = _call("elicit", mode)
    assert result.is_error
    assert "can't show that confirmation prompt" in _text(result)
    assert FakeSMTP.sent == []


def test_elicit_shows_bcc():
    decline = lambda m: ElicitResult(action="decline")  # noqa: E731
    _, prompts = _call("elicit", "legacy", decline, {**ARGS, "bcc": "boss@example.com"})
    assert "Bcc: boss@example.com" in prompts[0]


def test_elicit_checks_sender_before_asking():
    _, prompts = _call("elicit", "legacy", lambda m: ElicitResult(action="accept", content={"send": True}),
                       {**ARGS, "from_address": "ceo@bank.com"})
    assert prompts == [] and FakeSMTP.sent == []


@pytest.mark.parametrize("mode", PROTOCOLS)
def test_client_mode_sends_without_asking(mode):
    result, prompts = _call("client", mode, lambda m: pytest.fail("client mode must not elicit"))
    assert not result.is_error, _text(result)
    assert prompts == [] and len(FakeSMTP.sent) == 1


def test_confirmation_parameter_is_not_exposed():
    tool = next(t for t in _server("elicit")._tool_manager.list_tools() if t.name == "send_email")
    assert "confirmation" not in tool.parameters["properties"]


def test_instructions_follow_the_mode():
    assert "approval in chat" in p.instructions("client")
    assert "approval in chat" not in p.instructions("elicit")
    assert "prompt of its own" in p.instructions("elicit")
    assert "don't send it another way" in p.instructions("elicit")
    assert "another way" in p.send_email_confirmed.__doc__


@pytest.mark.parametrize("value", [None, "", "client", " Elicit "])
def test_confirm_mode_values(value):
    assert p.send_confirm_mode(value) in p.SEND_CONFIRM_MODES


def test_confirm_mode_typo_stops_the_server():
    with pytest.raises(SystemExit):
        p.send_confirm_mode("elcit")
