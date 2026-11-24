"""Task 1 (migration-governance): waivers, change metadata, sidecar loaders and result models."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from necro.gate_models import (
    GATE_IDS,
    AuditHeader,
    ChangeMeta,
    Check,
    GateResult,
    Sidecar,
    Verdict,
    Waiver,
    load_sidecar,
    parse_sidecar,
)
from necro.ledger import Approval

WAIVER = {
    "target": "line:57",
    "reason": "IPv6 is out of scope for this change",
    "approver": "Dana Reviewer",
    "expires_on": "2026-12-31",
}

TOML = """
[change]
change_id = "CHG-0042"
requested_by = "alex"
peer_reviewer = "sam"
cab_reference = "CAB-2026-11-28"
window_start = 2026-12-05T22:00:00Z
window_end = 2026-12-06T02:00:00Z

[[waivers]]
target = "line:57"
reason = "IPv6 is out of scope for this change"
approver = "Dana Reviewer"
expires_on = 2026-12-31

[[accepted_risks]]
target = "finding:AUT-0007"
reason = "Telnet to the DMZ host is removed in CHG-0043"
approver = "Dana Reviewer"
expires_on = 2027-01-31

[ledger_decisions.LED-0001]
approval = "accepted"
approver = "Dana Reviewer"
decided_at = "2026-11-27"
"""


# -- waivers ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target", ["line:57", "finding:AUT-0012", "ledger:LED-0003", "ledger:TGT-1"]
)
def test_a_waiver_targets_a_line_a_finding_or_a_ledger_entry(target: str) -> None:
    waiver = Waiver.model_validate({**WAIVER, "target": target})
    assert waiver.kind == target.split(":")[0] and waiver.subject == target.split(":")[1]


@pytest.mark.parametrize(
    "target", ["57", "line:0", "line:x", "rule:ACL#1", "finding:", "ledger:a b"]
)
def test_other_targets_are_refused(target: str) -> None:
    with pytest.raises(ValidationError, match="target must be"):
        Waiver.model_validate({**WAIVER, "target": target})


@pytest.mark.parametrize("field", ["reason", "approver"])
def test_a_waiver_needs_a_reason_and_a_named_approver(field: str) -> None:
    with pytest.raises(ValidationError, match="must not be empty"):
        Waiver.model_validate({**WAIVER, field: "   "})
    with pytest.raises(ValidationError):
        Waiver.model_validate({k: v for k, v in WAIVER.items() if k != field})


def test_a_waiver_is_valid_through_its_expiry_day_and_not_after() -> None:
    waiver = Waiver.model_validate(WAIVER)
    assert waiver.valid_on(date(2026, 12, 30))
    assert waiver.valid_on(date(2026, 12, 31))  # expires today: still valid
    assert not waiver.valid_on(date(2027, 1, 1))


def test_waivers_are_immutable_and_reject_unknown_fields() -> None:
    waiver = Waiver.model_validate(WAIVER)
    with pytest.raises(ValidationError):
        waiver.reason = "something else"  # type: ignore[misc]
    with pytest.raises(ValidationError, match="Extra inputs"):
        Waiver.model_validate({**WAIVER, "expires": "2026-12-31"})


# -- change metadata ------------------------------------------------------------------------------


def test_change_metadata_is_optional_but_the_window_must_be_in_order() -> None:
    assert ChangeMeta().change_id is None
    start = datetime(2026, 12, 5, 22, tzinfo=UTC)
    ChangeMeta(window_start=start, window_end=datetime(2026, 12, 6, 2, tzinfo=UTC))
    with pytest.raises(ValidationError, match="window_end must be after"):
        ChangeMeta(window_start=start, window_end=start)


# -- the sidecar ----------------------------------------------------------------------------------


def test_a_toml_sidecar_loads_every_section() -> None:
    sidecar = parse_sidecar(TOML, "toml")
    assert sidecar.change.change_id == "CHG-0042" and sidecar.change.peer_reviewer == "sam"
    assert sidecar.change.window_start == datetime(2026, 12, 5, 22, tzinfo=UTC)
    assert [w.target for w in sidecar.waivers] == ["line:57"]
    assert sidecar.waivers[0].expires_on == date(2026, 12, 31)
    assert [r.target for r in sidecar.accepted_risks] == ["finding:AUT-0007"]
    decision = sidecar.ledger_decisions["LED-0001"]
    assert decision.approval == Approval.accepted and decision.approver == "Dana Reviewer"


def test_the_same_sidecar_as_json_is_the_same_object() -> None:
    from_toml = parse_sidecar(TOML, "toml")
    from_json = parse_sidecar(from_toml.model_dump_json(), "json")
    assert from_json == from_toml


def test_files_are_loaded_by_suffix(tmp_path: Path) -> None:
    toml_file = tmp_path / "chg.toml"
    toml_file.write_text(TOML, encoding="utf-8")
    json_file = tmp_path / "chg.JSON"
    json_file.write_text(parse_sidecar(TOML, "toml").model_dump_json(), encoding="utf-8")
    assert load_sidecar(toml_file) == load_sidecar(json_file)
    other = tmp_path / "chg.yaml"
    other.write_text("waivers: []", encoding="utf-8")
    with pytest.raises(ValueError, match=r"\.json or \.toml"):
        load_sidecar(other)


def test_an_empty_sidecar_means_no_waivers_and_no_decisions() -> None:
    for sidecar in (parse_sidecar("", "toml"), parse_sidecar("{}", "json"), Sidecar()):
        assert sidecar.waivers == [] and sidecar.ledger_decisions == {}
        assert sidecar.change == ChangeMeta()


@pytest.mark.parametrize(
    ("text", "fmt", "message"),
    [
        ("[[waiver]]\ntarget = 'line:1'", "toml", "Extra inputs"),  # misspelled section
        ("not toml at all = = =", "toml", "not valid TOML"),
        ("{", "json", "not valid JSON"),
        ("[1, 2]", "json", "top level"),
        ('{"ledger_decisions": {"LED-0001": "accepted"}}', "json", "needs approval, approver"),
        (
            '{"ledger_decisions": {"LED-0001": {"approval": "accepted"}}}',
            "json",
            "needs an approver and a decided_at",
        ),
        (
            '{"accepted_risks": [{"target": "line:5", "reason": "r", "approver": "a",'
            ' "expires_on": "2027-01-01"}]}',
            "json",
            "targets a finding",
        ),
    ],
)
def test_a_bad_sidecar_is_refused_with_a_reason(text: str, fmt: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_sidecar(text, fmt)  # type: ignore[arg-type]


# -- result models --------------------------------------------------------------------------------


def test_result_models_hold_what_the_report_needs() -> None:
    check = Check(id="g1-confidence", ok=False, severity="error", detail="confidence 0.80 < 0.90")
    gate = GateResult(gate="G1", status="fail", checks=[check], blocking_reasons=[check.detail])
    audit = AuditHeader(
        tool_version="0.1.0",
        git_commit="abc1234",
        inputs={"source.cfg": "0" * 64},
        dialect="asa",
        os_version="8.2(5)",
        generated_at=datetime(2026, 11, 28, 12, tzinfo=UTC),
    )
    verdict = Verdict(
        value="NO-GO",
        gates=[gate],
        blocking_reasons=["G1: confidence 0.80 < 0.90"],
        conditions=[],
        waivers_used=[],
        audit=audit,
    )
    again = Verdict.model_validate_json(verdict.model_dump_json())
    assert again == verdict
    assert GATE_IDS == ("G1", "G2", "G3", "G4", "G5", "G6")
    with pytest.raises(ValidationError):
        GateResult(gate="G7", status="pass", checks=[], blocking_reasons=[])  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        Verdict(value="SAFE", gates=[], blocking_reasons=[], conditions=[], waivers_used=[])  # type: ignore[arg-type]
