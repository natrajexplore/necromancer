"""Task 9.3: the MCP server (FastMCP, stdio) and its five tools."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from mcp_server import build_server
from necro import mcp_tools
from tests.panos_helpers import SAMPLES

CONFIG = (SAMPLES / "pix-2006-hq.cfg").read_text(encoding="utf-8")
BACKEND = Path(__file__).resolve().parents[1]
TOOLS = {"exhume", "autopsy", "resurrect", "prove", "gate"}


def test_the_five_tools_are_registered_with_descriptions() -> None:
    registered = {t.name: t for t in build_server()._tool_manager.list_tools()}
    assert set(registered) == TOOLS
    assert all(t.description for t in registered.values())
    assert registered["prove"].parameters["required"] == ["config"]


def test_tools_return_json_ready_results() -> None:
    assert mcp_tools.exhume(CONFIG)["dialect"] == "pix"
    assert mcp_tools.autopsy(CONFIG)["findings"]
    raised = mcp_tools.resurrect(CONFIG)
    assert raised["config"].startswith("set ") and all("class" in e for e in raised["ledger"])
    proved = mcp_tools.prove(CONFIG, budget=30, seed=3)
    assert proved["passed"] is True and proved["proof"]["seed"] == 3
    json.dumps([proved, raised])  # fully serialisable


def test_refusals_are_structured_errors_not_exceptions() -> None:
    assert mcp_tools.exhume("hello\n")["error"]["code"] == "unknown-dialect"
    assert mcp_tools.prove(CONFIG, budget=20_001)["error"]["code"] == "invalid-budget"
    assert mcp_tools.prove(CONFIG, profile="huge")["error"]["code"] == "invalid-profile"
    cycle = (SAMPLES.parent / "broken-configs" / "asa-group-cycle.cfg").read_text(encoding="utf-8")
    assert mcp_tools.autopsy(cycle)["error"]["line_no"] > 0
    assert mcp_tools.exhume("!" * (2 * 1024 * 1024 + 1))["error"]["code"] == "too-large"


def test_gate_says_not_implemented_yet() -> None:
    error = mcp_tools.gate(CONFIG)["error"]
    assert error["code"] == "not-implemented" and "not implemented yet" in error["message"]


def test_secrets_are_not_in_tool_output() -> None:
    text = json.dumps([mcp_tools.exhume(CONFIG), mcp_tools.resurrect(CONFIG)])
    for token in ("8Ry2YjIyt7RRXU24", "2KFQnbNIdI.2KYOU", "n0t-a-real-community"):
        assert token in CONFIG and token not in text


def test_the_server_speaks_mcp_over_stdio_via_python_dash_m() -> None:
    """Start it the way .kiro/settings/mcp.json does, handshake, list and call a tool."""

    def message(payload: dict[str, object]) -> str:
        return json.dumps({"jsonrpc": "2.0", **payload}) + "\n"

    init = {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    }
    call = {"name": "gate", "arguments": {"config": CONFIG}}
    requests = [
        message({"id": 1, "method": "initialize", "params": init}),
        message({"method": "notifications/initialized"}),
        message({"id": 2, "method": "tools/list"}),
        message({"id": 3, "method": "tools/call", "params": call}),
    ]
    server = subprocess.Popen(
        [sys.executable, "-m", "mcp_server"],
        cwd=BACKEND,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    replies: dict[int, dict[str, object]] = {}
    try:
        assert server.stdin is not None and server.stdout is not None
        server.stdin.write("".join(requests))
        server.stdin.flush()  # keep stdin open: closing it stops the server before it answers
        while len(replies) < 3:
            line = server.stdout.readline()
            assert line, "the server closed stdout before answering"
            reply = json.loads(line)
            if "id" in reply:
                replies[reply["id"]] = reply
    finally:
        server.kill()
        server.communicate()
    assert replies[1]["result"]["serverInfo"]["name"] == "necromancer"
    assert {t["name"] for t in replies[2]["result"]["tools"]} == TOOLS
    content = json.loads(replies[3]["result"]["content"][0]["text"])
    assert content["error"]["code"] == "not-implemented"
