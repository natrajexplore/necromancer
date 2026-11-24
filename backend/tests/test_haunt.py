"""Haunt it (graveyard-ui 4.3): a deliberately broken candidate that only the proof sees.

The haunted proof must fail with a counterexample on every sample, and haunting must change
nothing else: not the emitted config, the ledger, the gate verdict or the Grimoire. The gate
and report routes refuse the flag.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Generator
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from mcp_server import build_server
from necro import mcp_tools, service
from necro.cli import main
from necro.emitters import emit_panos
from necro.haunt import HauntError, haunt_candidate
from necro.service import NecroError
from tests.panos_helpers import SAMPLES

SAMPLE_FILES = sorted(p.name for p in SAMPLES.glob("*.cfg"))
PIX = SAMPLES / "pix-2006-hq.cfg"
CONFIG = PIX.read_text(encoding="utf-8")
BUDGET = 60

# Only deny rules: nothing for the haunt to flip.
DENY_ONLY = """\
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 192.0.2.1 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 192.0.2.254 1
access-list OUT_IN extended deny ip any any
access-list IN_OUT extended deny ip any any
access-group OUT_IN in interface outside
access-group IN_OUT in interface inside
"""


@pytest.fixture(autouse=True)
def block_network() -> Generator[None, None, None]:
    """asyncio needs a loopback socketpair, so only name resolution and connects are blocked."""

    def _guard(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Network call attempted during test suite")

    with (
        patch.object(socket, "getaddrinfo", side_effect=_guard),
        patch.object(socket, "create_connection", side_effect=_guard),
    ):
        yield


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(rate_per_minute=1000))


def _text(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------- the rewrite itself

_R = "set rulebase security rules "


def test_the_rewrite_flips_only_the_first_enabled_allow_rule() -> None:
    text = f"{_R}r-1 action allow\n{_R}r-2 action allow\n{_R}necro-final-deny action deny\n"
    assert haunt_candidate(text).splitlines() == [
        f"{_R}r-1 action deny",
        f"{_R}r-2 action allow",
        f"{_R}necro-final-deny action deny",
    ]


def test_the_rewrite_skips_a_disabled_allow_rule() -> None:
    text = (
        f"{_R}r-1 action allow\n{_R}r-1 disabled yes\n"
        f"{_R}r-2 action allow\n{_R}necro-final-deny action deny\n"
    )
    assert haunt_candidate(text).splitlines() == [
        f"{_R}r-1 action allow",
        f"{_R}r-1 disabled yes",
        f"{_R}r-2 action deny",
        f"{_R}necro-final-deny action deny",
    ]


def test_the_rewrite_refuses_a_candidate_with_nothing_to_break() -> None:
    with pytest.raises(HauntError):
        haunt_candidate(f"{_R}necro-final-deny action deny\n")
    with pytest.raises(HauntError):  # the only allow rule is disabled
        haunt_candidate(f"{_R}r-1 action allow\n{_R}r-1 disabled yes\n")


@pytest.mark.parametrize("name", SAMPLE_FILES)
def test_the_rewrite_changes_exactly_one_line_of_every_sample_emission(name: str) -> None:
    emitted = emit_panos(service.load(_text(name))).text
    haunted = haunt_candidate(emitted)
    changed = [
        (a, b) for a, b in zip(emitted.splitlines(), haunted.splitlines(), strict=True) if a != b
    ]
    assert len(changed) == 1
    assert changed[0][0].endswith(" action allow") and changed[0][1].endswith(" action deny")


# ---------------------------------------------------------------- the proof fails everywhere


@pytest.mark.parametrize("name", SAMPLE_FILES)
def test_a_haunted_proof_fails_with_a_counterexample_on_every_sample(name: str) -> None:
    text = _text(name)
    clean = service.prove(text, budget=BUDGET, seed=1)
    haunted = service.prove(text, budget=BUDGET, seed=1, haunt=True)
    assert clean.passed and clean.haunted is False
    assert haunted.haunted is True and haunted.passed is False and haunted.proof.passed is False
    cex = haunted.proof.counterexample
    assert cex is not None
    assert cex.original.action.value == "permit" and cex.resurrected.action.value == "deny"
    # the same seed shrinks to the same packet
    again = service.prove(text, budget=BUDGET, seed=1, haunt=True).proof.counterexample
    assert again == cex


@pytest.mark.parametrize("name", SAMPLE_FILES)
def test_haunting_changes_nothing_but_the_proof(name: str) -> None:
    text = _text(name)
    before_config = service.resurrect(text)
    before_prove = service.prove(text, budget=BUDGET, seed=1)
    haunted = service.prove(text, budget=BUDGET, seed=1, haunt=True)
    after_config = service.resurrect(text)
    assert after_config == before_config  # emitted config, ledger and notes unchanged
    assert haunted.ledger_entries == before_prove.ledger_entries == len(before_config.ledger)
    assert haunted.blocking_lines == before_prove.blocking_lines
    assert haunted.proof.golden == before_prove.proof.golden


def test_haunting_leaves_the_verdict_and_the_grimoire_byte_identical() -> None:
    def report() -> tuple[str, str, str]:
        assessed = service.assess(CONFIG, None, budget=BUDGET, seed=1)
        response = service.grimoire_response(assessed)
        return response.verdict.value, response.body_sha256, response.markdown

    before = report()
    assert service.prove(CONFIG, budget=BUDGET, seed=1, haunt=True).passed is False
    assert report() == before


def test_a_candidate_with_nothing_to_haunt_is_a_structured_error() -> None:
    with pytest.raises(NecroError) as raised:
        service.prove(DENY_ONLY, budget=BUDGET, haunt=True)
    assert raised.value.code == "haunt-unavailable" and raised.value.kind == "input"
    assert service.prove(DENY_ONLY, budget=BUDGET).haunted is False  # unhaunted still works


# ---------------------------------------------------------------- the API


def _prove(client: TestClient, **body: object) -> Any:
    return client.post("/v1/prove", json={"config": CONFIG, "budget": BUDGET, "seed": 1, **body})


def test_api_prove_haunt_answers_haunted_with_a_failed_proof(client: TestClient) -> None:
    response = _prove(client, haunt=True)
    body = response.json()
    assert response.status_code == 200
    assert body["haunted"] is True and body["passed"] is False
    assert body["proof"]["counterexample"]["original"]["action"] == "permit"


def test_api_prove_without_haunt_is_unchanged(client: TestClient) -> None:
    for body in (_prove(client).json(), _prove(client, haunt=False).json()):
        assert body["haunted"] is False and body["passed"] is True
        assert body["proof"]["counterexample"] is None


def test_api_haunt_must_be_a_boolean(client: TestClient) -> None:
    response = _prove(client, haunt="please")
    assert response.status_code == 422 and response.json()["code"] == "invalid-request"


def test_api_prove_haunt_on_nothing_to_break_is_422(client: TestClient) -> None:
    response = client.post("/v1/prove", json={"config": DENY_ONLY, "budget": BUDGET, "haunt": True})
    assert response.status_code == 422 and response.json()["code"] == "haunt-unavailable"


@pytest.mark.parametrize("route", ["gate", "grimoire"])
def test_api_gate_and_grimoire_refuse_haunt(client: TestClient, route: str) -> None:
    refused = client.post(f"/v1/{route}", json={"config": CONFIG, "budget": BUDGET, "haunt": True})
    assert refused.status_code == 422
    body = refused.json()
    assert body["code"] == "invalid-request" and "haunt" in body["message"]
    allowed = client.post(
        f"/v1/{route}", json={"config": CONFIG, "budget": BUDGET, "seed": 1, "haunt": False}
    )
    assert allowed.status_code == 200


def test_api_haunting_does_not_change_resurrect_gate_or_grimoire(client: TestClient) -> None:
    def snapshot() -> tuple[object, object, object]:
        request = {"config": CONFIG, "budget": BUDGET, "seed": 1}
        resurrected = client.post("/v1/resurrect", json=request).json()
        gated = client.post("/v1/gate", json=request).json()
        gated["verdict"]["audit"].pop("generated_at")
        grimoire = client.post("/v1/grimoire", json=request).json()
        return resurrected, gated, grimoire["body_sha256"]

    before = snapshot()
    assert _prove(client, haunt=True).json()["passed"] is False
    assert snapshot() == before


# ---------------------------------------------------------------- the CLI


def _cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_prove_haunt_exits_one_and_says_haunted(capsys: pytest.CaptureFixture[str]) -> None:
    args = ("prove", str(PIX), "--budget", str(BUDGET), "--seed", "1")
    code, out, _ = _cli(capsys, *args, "--haunt", "--format", "json")
    assert code == 1
    body = json.loads(out)
    assert body["haunted"] is True and body["passed"] is False
    code, out, _ = _cli(capsys, *args, "--haunt")
    assert code == 1 and "haunted" in out and "FAIL" in out
    code, out, _ = _cli(capsys, *args, "--format", "json")
    assert code == 0 and json.loads(out)["haunted"] is False


@pytest.mark.parametrize("command", ["exhume", "autopsy", "resurrect", "gate", "grimoire"])
def test_cli_haunt_is_refused_for_every_other_command(
    capsys: pytest.CaptureFixture[str], command: str
) -> None:
    code, out, err = _cli(capsys, command, str(PIX), "--haunt")
    assert code == 2 and not out and "--haunt is only available for prove" in err


# ---------------------------------------------------------------- the MCP server


def test_mcp_prove_accepts_haunt_and_gate_does_not() -> None:
    registered = {t.name: t for t in build_server()._tool_manager.list_tools()}
    assert "haunt" in registered["prove"].parameters["properties"]
    assert "haunt" not in registered["gate"].parameters["properties"]
    haunted = mcp_tools.prove(CONFIG, budget=BUDGET, seed=1, haunt=True)
    assert haunted["haunted"] is True and haunted["passed"] is False
    clean = mcp_tools.prove(CONFIG, budget=BUDGET, seed=1)
    assert clean["haunted"] is False and clean["passed"] is True
    json.dumps([haunted, clean])


def test_mcp_haunt_on_nothing_to_break_is_a_structured_error() -> None:
    refused = mcp_tools.prove(DENY_ONLY, budget=BUDGET, haunt=True)
    assert refused["error"]["code"] == "haunt-unavailable"
