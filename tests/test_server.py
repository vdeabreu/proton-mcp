"""Remote server startup checks (run in a subprocess: importing server.py starts configuration)."""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_ENV = {
    "PUBLIC_URL": "https://mcp.example.com",
    "MCP_PASSWORD": "x" * 24,
    "PROTON_BRIDGE_USER": "a@b.c",
    "PROTON_BRIDGE_PASSWORD": "p",
}


def _import_server(tmp_path, **env):
    pythonpath = os.pathsep.join([ROOT, os.path.join(ROOT, "remote")])
    full = {**os.environ, **BASE_ENV, "DATA_DIR": str(tmp_path), "PYTHONPATH": pythonpath, **env}
    code = "import server; print(sorted(t.name for t in server.mcp._tool_manager.list_tools()))"
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, env=full)


def test_refuses_public_listen_address(tmp_path):
    r = _import_server(tmp_path, LISTEN_HOST="0.0.0.0")
    assert r.returncode != 0
    assert "not a loopback address" in r.stderr


def test_public_listen_needs_explicit_opt_in(tmp_path):
    r = _import_server(tmp_path, LISTEN_HOST="0.0.0.0", ALLOW_NON_LOOPBACK_LISTEN="true")
    assert r.returncode == 0, r.stderr


def test_send_disabled_by_default_remotely(tmp_path):
    r = _import_server(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "send_email" not in r.stdout and "read_email" in r.stdout


def test_send_enabled_remotely_on_request(tmp_path):
    r = _import_server(tmp_path, ENABLE_SEND="true")
    assert "send_email" in r.stdout


def test_send_confirm_elicit_remotely(tmp_path):
    full = {**os.environ, **BASE_ENV, "DATA_DIR": str(tmp_path), "ENABLE_SEND": "true", "PROTON_SEND_CONFIRM": "elicit",
            "PYTHONPATH": os.pathsep.join([ROOT, os.path.join(ROOT, "remote")])}
    code = (
        "import server\n"
        "from mcp.server.mcpserver.resolve import find_resolved_parameters\n"
        "tool = next(t for t in server.mcp._tool_manager.list_tools() if t.name == 'send_email')\n"
        "print(sorted(tool.parameters['properties']))\n"
        "print(sorted(find_resolved_parameters(tool.fn)))\n"
        "print(server.mcp.instructions)\n"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, env=full)
    assert r.returncode == 0, r.stderr
    schema, resolved, instructions = r.stdout.splitlines()[:3]
    assert "confirmation" not in schema and "'to'" in schema
    assert resolved == "['confirmation']"
    assert "prompt of its own" in instructions


def test_send_confirm_typo_refuses_to_start(tmp_path):
    r = _import_server(tmp_path, ENABLE_SEND="true", PROTON_SEND_CONFIRM="elcit")
    assert r.returncode != 0
    assert "send confirmation mode" in r.stderr
