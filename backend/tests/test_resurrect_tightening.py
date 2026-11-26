"""Requirement 5 end to end: proposals, a separate tightened artifact, its ledger and its proof.

Covers ``service.resurrect``, ``POST /v1/resurrect``, the MCP ``resurrect`` tool and
``necro resurrect --tightening``. The baseline must be identical with or without a selection
(governance R1), and a tightened artifact never travels without its ledger.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from necro import mcp_tools, service
from necro.cli import main
from necro.ir import LedgerClass
from necro.ledger import Approval
from necro.schemas import Proposal, ResurrectResult, TighteningSelection
from necro.service import NecroError
from necro.tighten import ApprovalDecision, Choice, RemediationKind
from tests.gov_helpers import secret_tokens
from tests.panos_helpers import SAMPLES

DIALECTS = {
    "pix-2006-hq": "pix",
    "asa-8.2-branch": "asa",
    "asa-9.8-dc": "asa",
    "ios-12-edge": "ios",
}
NETWORKS = ["10.0.0.0/8"]  # RFC 1918
FAST = 40  # examples per context: the tests check wiring, not the proof budget


def _text(name: str) -> str:
    return (SAMPLES / f"{name}.cfg").read_text(encoding="utf-8")


PIX = _text("pix-2006-hq")


def _all_choices(proposals: list[Proposal]) -> list[Choice]:
    """Accept every proposal. Narrowing gets a confirmed private network."""
    return [
        Choice(
            finding_id=p.finding_id,
            kind=p.kind,
            networks=NETWORKS if p.needs_networks else [],
        )
        for p in proposals
    ]


def _selection(result: ResurrectResult) -> TighteningSelection:
    return TighteningSelection(choices=_all_choices(result.proposals))


@pytest.fixture(scope="module")
def pix_baseline() -> ResurrectResult:
    return service.resurrect(PIX, "pix")


@pytest.fixture(scope="module")
def pix_tightened(pix_baseline: ResurrectResult) -> ResurrectResult:
    return service.resurrect(PIX, "pix", tightening=_selection(pix_baseline), budget=FAST, seed=5)


@pytest.fixture(autouse=True)
def block_network() -> Generator[None, None, None]:
    """Replaces the conftest guard (same name, as in test_api.py): asyncio needs a loopback
    socketpair for its event loop. Name resolution and outbound connections stay blocked."""

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


# --- proposals without a selection -------------------------------------------------------------


@pytest.mark.parametrize("name", DIALECTS)
def test_without_a_selection_the_result_holds_proposals_and_no_tightened_artifact(
    name: str,
) -> None:
    result = service.resurrect(_text(name), DIALECTS[name])
    assert result.tightened is None
    assert result.proposals
    assert all(p.summary and p.rule_ref and p.finding_id for p in result.proposals)
    assert len({p.finding_id for p in result.proposals}) == len(result.proposals)


def test_every_remediation_kind_is_proposed_somewhere() -> None:
    kinds: set[RemediationKind] = set()
    for name, dialect in DIALECTS.items():
        kinds |= {p.kind for p in service.resurrect(_text(name), dialect).proposals}
    assert kinds == set(RemediationKind)


def test_only_narrow_any_needs_confirmed_networks(pix_baseline: ResurrectResult) -> None:
    assert any(p.needs_networks for p in pix_baseline.proposals)
    for p in pix_baseline.proposals:
        assert p.needs_networks == (p.kind == RemediationKind.narrow_any)


def test_proposals_are_ordered_most_severe_first(pix_baseline: ResurrectResult) -> None:
    order = ["critical", "high", "medium", "low"]
    ranks = [order.index(p.severity) for p in pix_baseline.proposals]
    assert ranks == sorted(ranks)


def test_snmp_v2c_gets_an_advisory_that_names_snmpv3(pix_baseline: ResurrectResult) -> None:
    snmp = [p for p in pix_baseline.proposals if p.rule_ref.startswith("mgmt:snmp")]
    assert snmp and all(p.kind == RemediationKind.advise for p in snmp)
    assert all("SNMPv3" in p.summary for p in snmp)


# --- a selection: separate artifact, own ledger, own proof -------------------------------------


def test_the_baseline_is_identical_with_and_without_a_selection(
    pix_baseline: ResurrectResult, pix_tightened: ResurrectResult
) -> None:
    for field in ("config", "config_lines", "ledger", "unsupported", "notes", "blocking"):
        assert getattr(pix_tightened, field) == getattr(pix_baseline, field)
    assert pix_tightened.proposals == pix_baseline.proposals


def test_the_tightened_artifact_is_separate_and_stricter(pix_tightened: ResurrectResult) -> None:
    t = pix_tightened.tightened
    assert t is not None
    assert t.config != pix_tightened.config and t.config.startswith("set ")
    assert t.config_lines == len(t.config.splitlines())
    assert t.applied
    assert t.validation_errors == []


def test_the_tightened_ledger_has_tightening_entries_with_finding_refs(
    pix_tightened: ResurrectResult,
) -> None:
    t = pix_tightened.tightened
    assert t is not None
    tightening = [e for e in t.ledger if e.entry_class == LedgerClass.tightening]
    assert tightening and all(e.finding_ref for e in tightening)
    assert {e.finding_ref for e in tightening} <= set(t.applied)
    assert all(e.approval == Approval.pending for e in tightening)
    changed = [e for e in tightening if not e.informational]
    assert changed and all(e.old_action != e.new_action for e in changed)
    # the baseline ledger never carries a tightening entry
    assert all(e.entry_class != LedgerClass.tightening for e in pix_tightened.ledger)


def test_the_tightened_artifact_has_its_own_passing_proof(pix_tightened: ResurrectResult) -> None:
    t = pix_tightened.tightened
    assert t is not None and t.proof is not None
    assert t.passed and t.proof.passed and t.proof_error == ""
    assert t.proof.seed == 5 and t.proof.budget == FAST


def test_tightening_does_not_depend_on_the_proof_seed(pix_baseline: ResurrectResult) -> None:
    one = service.resurrect(PIX, "pix", tightening=_selection(pix_baseline), budget=10, seed=5)
    two = service.resurrect(PIX, "pix", tightening=_selection(pix_baseline), budget=10, seed=6)
    assert one.tightened is not None and two.tightened is not None
    assert one.tightened.config == two.tightened.config
    assert [e.id for e in one.tightened.ledger] == [e.id for e in two.tightened.ledger]


@pytest.mark.parametrize("name", DIALECTS)
def test_every_sample_tightens_and_proves(name: str) -> None:
    base = service.resurrect(_text(name), DIALECTS[name])
    result = service.resurrect(
        _text(name), DIALECTS[name], tightening=_selection(base), budget=20, seed=1
    )
    t = result.tightened
    assert t is not None and t.proof is not None and t.passed
    assert result.config == base.config


def test_an_empty_selection_gives_an_unchanged_but_separate_artifact(
    pix_baseline: ResurrectResult,
) -> None:
    result = service.resurrect(PIX, "pix", tightening=TighteningSelection(), budget=10)
    t = result.tightened
    assert t is not None and t.applied == [] and t.passed
    assert t.config == pix_baseline.config


def test_a_rejected_finding_stays_in_the_ledger_but_is_not_applied(
    pix_baseline: ResurrectResult,
) -> None:
    target = next(p for p in pix_baseline.proposals if p.kind == RemediationKind.replace_service)
    rejected = ApprovalDecision(
        approval=Approval.rejected, approver="A. Reviewer", decided_at="2026-11-24T12:00:00Z"
    )
    selection = TighteningSelection(
        choices=[Choice(finding_id=target.finding_id)], approvals={target.finding_id: rejected}
    )
    t = service.resurrect(PIX, "pix", tightening=selection, budget=10).tightened
    assert t is not None
    assert target.finding_id not in t.applied and t.config == pix_baseline.config
    mine = [e for e in t.ledger if e.finding_ref == target.finding_id]
    assert mine and all(e.approval == Approval.rejected for e in mine)


def test_a_choice_that_is_not_offered_is_reported_as_skipped(
    pix_baseline: ResurrectResult,
) -> None:
    removal = next(p for p in pix_baseline.proposals if p.kind == RemediationKind.remove_rule)
    wrong = Choice(finding_id=removal.finding_id, kind=RemediationKind.narrow_any)
    selection = TighteningSelection(choices=[wrong])
    t = service.resurrect(PIX, "pix", tightening=selection, budget=10).tightened
    assert t is not None and t.applied == []
    assert [s.finding_id for s in t.skipped] == [removal.finding_id]


def test_advisories_are_notes_and_change_no_rule(pix_baseline: ResurrectResult) -> None:
    advise = [p for p in pix_baseline.proposals if p.kind == RemediationKind.advise]
    selection = TighteningSelection(choices=[Choice(finding_id=p.finding_id) for p in advise])
    t = service.resurrect(PIX, "pix", tightening=selection, budget=10).tightened
    assert t is not None and t.applied == [] and len(t.notes) == len(advise)
    assert t.config == pix_baseline.config


def test_unknown_and_duplicate_finding_ids_are_input_errors(
    pix_baseline: ResurrectResult,
) -> None:
    unknown = TighteningSelection(choices=[Choice(finding_id="AUT-9999")])
    with pytest.raises(NecroError) as err:
        service.resurrect(PIX, "pix", tightening=unknown, budget=10)
    assert err.value.code == "invalid-tightening" and "AUT-9999" in err.value.message
    known = pix_baseline.proposals[0].finding_id
    twice = TighteningSelection(choices=[Choice(finding_id=known)] * 2)
    with pytest.raises(NecroError) as err2:
        service.resurrect(PIX, "pix", tightening=twice, budget=10)
    assert err2.value.code == "invalid-tightening"


def test_the_proof_budget_is_checked_only_when_tightening() -> None:
    assert service.resurrect(PIX, "pix", budget=999_999).tightened is None
    with pytest.raises(NecroError) as err:
        service.resurrect(PIX, "pix", tightening=TighteningSelection(), budget=999_999)
    assert err.value.code == "invalid-budget"


def test_confirmed_networks_must_be_valid_ipv4() -> None:
    for bad in ("not-a-network", "2001:db8::/32", "10.0.0.1/8"):
        with pytest.raises(ValueError):
            Choice(finding_id="AUT-0001", networks=[bad])


def test_golden_flows_run_against_the_tightened_artifact(
    pix_baseline: ResurrectResult,
) -> None:
    golden = service.golden_for("pix-2006-hq")
    result = service.resurrect(
        PIX, "pix", tightening=_selection(pix_baseline), budget=10, golden=golden
    )
    t = result.tightened
    assert t is not None and t.proof is not None
    assert t.proof.golden.total == len(golden) > 0


def test_a_tightened_result_never_holds_a_secret(pix_tightened: ResurrectResult) -> None:
    blob = pix_tightened.model_dump_json(by_alias=True)
    tokens = secret_tokens(PIX)
    assert tokens and not [t for t in tokens if t in blob]


# --- API ----------------------------------------------------------------------------------------


def test_api_without_a_selection_returns_proposals(client: TestClient) -> None:
    response = client.post("/v1/resurrect", json={"config": PIX})
    assert response.status_code == 200
    body = response.json()
    assert body["tightened"] is None
    assert {p["kind"] for p in body["proposals"]} >= {"remove-rule", "replace-service"}
    assert {"finding_id", "severity", "rule_ref", "summary", "needs_networks"} <= set(
        body["proposals"][0]
    )


def test_api_with_a_selection_returns_a_separate_tightened_artifact(
    client: TestClient, pix_baseline: ResurrectResult
) -> None:
    plain = client.post("/v1/resurrect", json={"config": PIX}).json()
    choices = [c.model_dump() for c in _all_choices(pix_baseline.proposals)]
    response = client.post(
        "/v1/resurrect",
        json={"config": PIX, "tightening": {"choices": choices}, "budget": 20, "seed": 3},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["config"] == plain["config"] and body["ledger"] == plain["ledger"]
    t = body["tightened"]
    assert t["config"] != body["config"] and t["passed"] is True
    assert t["proof"]["seed"] == 3 and t["ledger"]
    assert "tightening" in {e["class"] for e in t["ledger"]}
    assert not [s for s in secret_tokens(PIX) if s in response.text]


def test_api_rejects_a_bad_selection_with_a_structured_error(client: TestClient) -> None:
    unknown = {"choices": [{"finding_id": "AUT-9999"}]}
    response = client.post("/v1/resurrect", json={"config": PIX, "tightening": unknown})
    assert response.status_code == 422 and response.json()["code"] == "invalid-tightening"
    bad_net = {"choices": [{"finding_id": "AUT-0001", "networks": ["nope"]}]}
    response = client.post("/v1/resurrect", json={"config": PIX, "tightening": bad_net})
    assert response.status_code == 422 and response.json()["code"] == "invalid-request"
    response = client.post(
        "/v1/resurrect", json={"config": PIX, "tightening": {"choices": []}, "budget": 20_001}
    )
    assert response.status_code == 422


def test_api_accepts_an_empty_tightening_object(client: TestClient) -> None:
    response = client.post("/v1/resurrect", json={"config": PIX, "tightening": {}, "budget": 5})
    assert response.status_code == 200 and response.json()["tightened"]["applied"] == []


# --- MCP ----------------------------------------------------------------------------------------


def test_mcp_resurrect_returns_proposals_and_an_optional_tightened_artifact(
    pix_baseline: ResurrectResult,
) -> None:
    plain = mcp_tools.resurrect(PIX)
    assert plain["proposals"] and plain["tightened"] is None
    choices = [c.model_dump() for c in _all_choices(pix_baseline.proposals)]
    tightened = mcp_tools.resurrect(PIX, tightening={"choices": choices}, budget=20, seed=2)
    assert tightened["config"] == plain["config"]
    assert tightened["tightened"]["passed"] is True
    json.dumps(tightened)


def test_mcp_resurrect_refuses_a_bad_selection_with_a_structured_error() -> None:
    bad = mcp_tools.resurrect(PIX, tightening={"choices": [{"kind": "remove-rule"}]})
    assert bad["error"]["code"] == "invalid-tightening"
    unknown = mcp_tools.resurrect(PIX, tightening={"choices": [{"finding_id": "AUT-9999"}]})
    assert unknown["error"]["code"] == "invalid-tightening"


# --- CLI ----------------------------------------------------------------------------------------


def _selection_file(tmp_path: Path, result: ResurrectResult) -> Path:
    path = tmp_path / "tightening.json"
    path.write_text(_selection(result).model_dump_json(), encoding="utf-8")
    return path


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_lists_proposals_without_a_selection(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(capsys, "resurrect", str(SAMPLES / "pix-2006-hq.cfg"), "--format", "json")
    body = json.loads(out)
    assert code == 0 and body["proposals"] and body["tightened"] is None


def test_cli_with_a_selection_adds_a_tightened_artifact(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, pix_baseline: ResurrectResult
) -> None:
    cfg = str(SAMPLES / "pix-2006-hq.cfg")
    flags = ("--tightening", str(_selection_file(tmp_path, pix_baseline)), "--budget", "20")
    code, out, _ = _run(capsys, "resurrect", cfg, "--format", "json", *flags)
    body = json.loads(out)
    assert code == 0 and body["tightened"]["passed"] is True
    assert body["tightened"]["config"] != body["config"]

    _, baseline_out, _ = _run(capsys, "resurrect", cfg, *flags)
    _, tightened_out, _ = _run(capsys, "resurrect", cfg, *flags, "--artifact", "tightened")
    assert baseline_out.strip() == body["config"].strip()
    assert tightened_out.strip() == body["tightened"]["config"].strip()

    code, md, _ = _run(capsys, "resurrect", cfg, "--format", "md", *flags)
    assert code == 0 and "Tightened ledger (separate change)" in md
    assert "Remediation proposals" in md


def test_cli_exits_1_when_the_tightened_proof_does_not_pass(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, pix_baseline: ResurrectResult
) -> None:
    from unittest.mock import patch

    cfg = str(SAMPLES / "pix-2006-hq.cfg")
    flags = ("--tightening", str(_selection_file(tmp_path, pix_baseline)), "--budget", "5")
    with patch("necro.service_tighten.run_prove", side_effect=service.ProofInputError("x")):
        code, _, _ = _run(capsys, "resurrect", cfg, "--format", "json", *flags)
    assert code == 1


def test_a_proof_that_cannot_run_is_reported_not_raised(pix_baseline: ResurrectResult) -> None:
    from unittest.mock import patch

    with patch("necro.service_tighten.run_prove", side_effect=service.ProofInputError("no go")):
        result = service.resurrect(PIX, "pix", tightening=_selection(pix_baseline), budget=5)
    t = result.tightened
    assert t is not None and t.proof is None and t.proof_error == "no go" and not t.passed


def test_cli_option_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    cfg = str(SAMPLES / "pix-2006-hq.cfg")
    empty = tmp_path / "t.json"
    empty.write_text("{}", encoding="utf-8")
    code, _, err = _run(capsys, "autopsy", cfg, "--tightening", str(empty))
    assert code == 2 and "--tightening is only available for resurrect" in err
    code, _, err = _run(capsys, "resurrect", cfg, "--artifact", "tightened")
    assert code == 2 and "needs --tightening" in err
    broken = tmp_path / "broken.json"
    broken.write_text('{"choices": "x"}', encoding="utf-8")
    code, _, err = _run(capsys, "resurrect", cfg, "--tightening", str(broken))
    assert code == 2 and "invalid-tightening" in err
    code, _, err = _run(capsys, "resurrect", cfg, "--tightening", str(tmp_path / "missing.json"))
    assert code == 2 and "unreadable" in err
