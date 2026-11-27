"""Requirement 5.5 and 5.6: the tightened artifact is gated as a separate verdict.

On pix-2006-hq the baseline stays NO-GO (G5: LED-0001 pending, G6: AUT-0008 critical). The
tightened artifact drops the telnet rule behind AUT-0008, so G6 is judged on the findings of the
tightened policy. These tests run at the ci budget, because a GO verdict needs it.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Generator
from functools import cache
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from necro import mcp_tools, report, service
from necro.assessment import Assessment, _tightened_sidecar, assemble, tightened_findings
from necro.autopsy import analyze
from necro.cli import main
from necro.gate_models import Sidecar
from necro.ir import Action, LedgerClass
from necro.ledger import Approval, LedgerEntry, make_entry
from necro.schemas import TighteningSelection
from tests.gov_helpers import NOW, TODAY
from tests.panos_helpers import SAMPLES

CONFIG = (SAMPLES / "pix-2006-hq.cfg").read_text(encoding="utf-8")
WHEN = "2026-11-24T10:00:00+00:00"


def _selection(*, kind: str | None = None) -> TighteningSelection:
    choice: dict[str, object] = {"finding_id": "AUT-0008"}
    if kind:
        choice["kind"] = kind
        choice["networks"] = ["10.0.0.0/8"]
    return TighteningSelection.model_validate(
        {
            "choices": [choice],
            "approvals": {
                "AUT-0008": {
                    "approval": "accepted",
                    "approver": "A. Lead",
                    "decided_at": WHEN,
                    "reason": "telnet from outside is not needed",
                }
            },
        }
    )


def _decision(approval: str) -> dict[str, object]:
    return {
        "approval": approval,
        "approver": "A. Lead",
        "decided_at": WHEN,
        "reason": "management profile reviewed",
    }


def _sidecar(approval: str = "accepted") -> Sidecar:
    return Sidecar.model_validate({"ledger_decisions": {"LED-0001": _decision(approval)}})


@cache
def _assessed() -> Assessment:
    return service.assess(
        CONFIG,
        "pix",
        golden=service.golden_for("pix-2006-hq"),
        input_name="pix-2006-hq",
        tightening=_selection(),
        today=TODAY,
        now=NOW,
    )


@cache
def _not_applied() -> Assessment:
    """AUT-0008 is accepted, but the remediation chosen for it is not offered, so it is skipped."""
    return service.assess(
        CONFIG,
        "pix",
        golden=service.golden_for("pix-2006-hq"),
        input_name="pix-2006-hq",
        tightening=_selection(kind="narrow-any"),
        today=TODAY,
        now=NOW,
    )


def _judge(a: Assessment, sidecar: Sidecar) -> Assessment:
    return assemble(a.core, sidecar, TODAY, NOW)


def _blocking(a: Assessment) -> list[str]:
    assert a.tightened is not None
    return a.tightened.verdict.blocking_reasons


def test_the_baseline_stays_no_go_and_is_the_same_with_or_without_a_selection() -> None:
    plain = service.assess(
        CONFIG, "pix", golden=service.golden_for("pix-2006-hq"), today=TODAY, now=NOW
    )
    with_selection = _judge(_assessed(), Sidecar())
    assert plain.verdict.value == with_selection.verdict.value == "NO-GO"
    assert plain.verdict.blocking_reasons == with_selection.verdict.blocking_reasons
    assert [g.status for g in plain.verdict.gates] == [
        g.status for g in with_selection.verdict.gates
    ]
    assert plain.core.emission.text == with_selection.core.emission.text
    assert plain.tightened is None and with_selection.tightened is not None


def test_the_tightened_artifact_reaches_go_with_aut_0008_and_led_0001_accepted() -> None:
    a = _judge(_assessed(), _sidecar())
    assert a.tightened is not None
    assert _blocking(a) == []
    assert a.tightened.verdict.value == "GO"
    assert all(g.status == "pass" for g in a.tightened.verdict.gates)
    # the baseline is still judged on its own findings: AUT-0008 is open there
    assert a.verdict.value == "NO-GO"
    assert any("AUT-0008" in r for r in a.verdict.blocking_reasons)


def test_g4_of_the_tightened_artifact_uses_its_own_proof_and_golden_flows() -> None:
    a = _judge(_assessed(), _sidecar())
    assert a.tightened is not None
    proof = a.tightened.core.proof
    assert proof is not None and proof is not a.core.proof
    assert proof.budget >= 5000 and proof.golden.total == 16
    g4 = a.tightened.verdict.gates[3]
    assert g4.gate == "G4" and g4.status == "pass"
    assert any(c.id == "g4-golden" and c.ok for c in g4.checks)


def test_g6_clears_a_finding_only_because_the_artifact_no_longer_has_it() -> None:
    a = _judge(_assessed(), _sidecar())
    assert a.tightened is not None
    assert "outside_in#5" not in a.tightened.core.artifact.emission.text
    left = {(f.type.value, f.rule_ref) for f in a.tightened.core.findings}
    first = {(f.type.value, f.rule_ref) for f in a.core.findings}
    assert ("insecure-service", "outside_in#5") not in left
    assert ("insecure-service", "outside_in#5") in first


def test_an_accepted_proposal_whose_change_is_not_in_the_artifact_still_fails_g6() -> None:
    a = _judge(_not_applied(), _sidecar())
    assert a.tightened is not None
    assert a.tightened.core.artifact.result.applied == []
    assert a.tightened.core.artifact.result.skipped
    assert a.tightened.verdict.value == "NO-GO"
    assert any(r.startswith("G6:") and "AUT-0008" in r for r in _blocking(a))


def test_rejecting_a_like_for_like_entry_still_fails_g5() -> None:
    a = _judge(_assessed(), _sidecar("rejected"))
    assert any(r.startswith("G5:") and "LED-0001" in r for r in _blocking(a))
    assert any(r.startswith("G5:") and "LED-0001" in r for r in a.verdict.blocking_reasons)


def test_a_pending_like_for_like_entry_blocks_the_tightened_artifact_too() -> None:
    a = _judge(_assessed(), Sidecar())
    assert any(r.startswith("G5:") and "LED-0001" in r for r in _blocking(a))


def test_a_decision_carries_its_reason_into_the_ledger_and_the_report() -> None:
    a = _judge(_assessed(), _sidecar())
    assert a.tightened is not None
    entry = next(e for e in a.tightened.ledger if e.id == "LED-0001")
    assert entry.approval == Approval.accepted and entry.approver == "A. Lead"
    assert entry.decision_reason == "management profile reviewed"
    assert "management profile reviewed" in report.render_md(a)


def test_the_grimoire_shows_both_verdicts_and_names_the_artifacts_in_the_title() -> None:
    a = _judge(_assessed(), _sidecar())
    text = report.render_md(a)
    title = "# Grimoire: migration evidence report: pix-2006-hq (baseline and tightened"
    assert text.startswith(title)
    assert "Readiness verdict, baseline artifact (like for like): NO-GO." in text
    assert "Readiness verdict, tightened artifact (a separate change): GO." in text
    plain = service.assess(CONFIG, "pix", budget=40, today=TODAY, now=NOW)
    assert report.title_of(plain).endswith("(baseline artifact)")


def test_tgt_entries_say_which_service_replaces_which() -> None:
    a = _assessed()
    assert a.tightened is not None
    reasons = [e.reason for e in a.tightened.core.artifact.result.ledger]
    assert any("ssh (22/tcp) replaces telnet (23/tcp)" in r for r in reasons)


def _entry(reason: str) -> LedgerEntry:
    made = make_entry(LedgerClass.to_the_box, reason, "any", Action.permit, Action.deny, [])
    return made.model_copy(update={"id": "LED-0001"})


def test_a_decision_on_an_id_that_names_different_entries_is_not_applied_to_the_tightened() -> None:
    kept, notes = _tightened_sidecar(_sidecar(), [_entry("one")], [_entry("two")])
    assert "LED-0001" not in kept.ledger_decisions and len(notes) == 1
    same, none = _tightened_sidecar(_sidecar(), [_entry("one")], [_entry("one")])
    assert "LED-0001" in same.ledger_decisions and none == []


def test_tightened_findings_keep_baseline_ids_and_new_ones_cannot_collide() -> None:
    a = _assessed()
    assert a.tightened is not None
    base_ids = {f.id for f in a.core.findings}
    for f in a.tightened.core.findings:
        assert f.id in base_ids or f.id.endswith("-T")
    again = tightened_findings(a.core.findings, a.tightened.core.artifact.result.policy)
    assert [f.id for f in again] == [f.id for f in a.tightened.core.findings]
    assert len(analyze(a.core.policy)) == len(a.core.findings)


# -- interfaces ---------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def block_network() -> Generator[None, None, None]:
    """Replaces the conftest guard: asyncio needs a loopback socketpair for the test client."""

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


def _body(**extra: object) -> dict[str, object]:
    return {
        "config": CONFIG,
        "sample": "pix-2006-hq",
        "sidecar": {"ledger_decisions": {"LED-0001": _decision("accepted")}},
        "tightening": json.loads(_selection().model_dump_json()),
        **extra,
    }


def test_api_gate_returns_both_verdicts(client: TestClient) -> None:
    response = client.post("/v1/gate", json=_body())
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"]["value"] == "NO-GO"
    assert body["tightened"]["verdict"]["value"] == "GO"
    assert body["tightened"]["accepted"] == 1 and body["tightened"]["applied"] == ["AUT-0008"]
    assert {e["id"] for e in body["ledger"]} == {"LED-0001"}
    decided = next(e for e in body["tightened"]["ledger"] if e["id"] == "LED-0001")
    assert decided["approval"] == "accepted" and decided["decision_reason"]


def test_api_gate_without_a_selection_has_no_tightened_verdict(client: TestClient) -> None:
    body = _body()
    del body["tightening"]
    response = client.post("/v1/gate", json=body)
    assert response.status_code == 200 and response.json()["tightened"] is None


def test_api_grimoire_names_the_sample_in_the_title_not_config(client: TestClient) -> None:
    body = client.post("/v1/grimoire", json=_body()).json()
    first = body["markdown"].splitlines()[0]
    assert "pix-2006-hq" in first and ": config" not in first
    assert "<title>Grimoire: migration evidence report: pix-2006-hq" in body["html"]
    assert body["tightened"]["verdict"]["value"] == "GO"


def test_api_refuses_a_haunted_candidate_for_both_verdicts(client: TestClient) -> None:
    for path in ("gate", "grimoire"):
        response = client.post(f"/v1/{path}", json=_body(haunt=True))
        assert response.status_code == 422


def test_api_rejects_an_unknown_finding_in_the_selection(client: TestClient) -> None:
    bad = {"choices": [{"finding_id": "AUT-9999"}], "approvals": {}}
    response = client.post("/v1/gate", json=_body(tightening=bad, budget=40))
    assert response.status_code == 422 and response.json()["code"] == "invalid-tightening"


def test_cli_gate_takes_a_tightening_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tightening = tmp_path / "tightening.json"
    tightening.write_text(_selection().model_dump_json(), encoding="utf-8")
    sidecar = tmp_path / "sidecar.json"
    sidecar.write_text(json.dumps({"ledger_decisions": {"LED-0001": _decision("accepted")}}))
    sample = SAMPLES / "pix-2006-hq.cfg"
    code = main(["gate", str(sample), "--tightening", str(tightening), "--sidecar", str(sidecar)])
    out = capsys.readouterr().out
    assert code == 1  # the baseline is NO-GO
    assert "verdict (baseline)" in out and "verdict (tightened, separate change)" in out
    assert "Tightened gates (separate change)" in out


def test_cli_rejects_tightening_for_other_commands(capsys: pytest.CaptureFixture[str]) -> None:
    sample = SAMPLES / "pix-2006-hq.cfg"
    assert main(["prove", str(sample), "--tightening", str(sample)]) == 2
    assert "only available for resurrect, gate and grimoire" in capsys.readouterr().err


def test_mcp_gate_takes_the_same_selection() -> None:
    result = mcp_tools.gate(
        CONFIG,
        "pix",
        sidecar={"ledger_decisions": {"LED-0001": _decision("accepted")}},
        sample="pix-2006-hq",
        tightening=json.loads(_selection().model_dump_json()),
    )
    assert result["verdict"]["value"] == "NO-GO"
    assert result["tightened"]["verdict"]["value"] == "GO"
    bad = mcp_tools.gate(CONFIG, "pix", budget=40, tightening={"choices": "x"})
    assert bad["error"]["code"] == "invalid-tightening"
