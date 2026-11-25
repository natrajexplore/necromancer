"""Gates G1, G2, G5 and G6: a pass and a fail case for every blocking condition."""

from __future__ import annotations

import dataclasses
from datetime import date, timedelta

import pytest

from necro.emitters.panos import PanosEmission, emit_panos
from necro.findings import Finding, FindingType, Severity
from necro.gate_models import Check, Sidecar, Waiver
from necro.gates import find_waiver, gate_g1, gate_g2, gate_g5, gate_g6, result
from necro.ir import Action, Dialect, LedgerClass, LineRecord, Policy, PolicyMode, UnparsedLine
from necro.ledger import Approval, LedgerEntry
from necro.parsers import parse_config
from necro.tighten import ApprovalDecision
from tests.panos_helpers import SAMPLES

TODAY = date(2026, 11, 21)
NO_SIDECAR = Sidecar()


def sample(name: str, dialect: Dialect) -> Policy:
    return parse_config((SAMPLES / name).read_text(encoding="utf-8"), dialect)


@pytest.fixture(scope="module")
def asa82() -> Policy:
    return sample("asa-8.2-branch.cfg", Dialect.asa)


@pytest.fixture(scope="module")
def emission(asa82: Policy) -> PanosEmission:
    return emit_panos(asa82)


def waiver(target: str, expires_on: date = TODAY) -> Waiver:
    return Waiver(target=target, reason="tracked in the change", approver="Dana Reviewer",
                  expires_on=expires_on)  # fmt: skip


def failing(checks: list[Check]) -> list[Check]:
    return [c for c in checks if not c.ok]


# -- result / waivers --------------------------------------------------------------------------


def test_warnings_alone_do_not_block() -> None:
    warning = Check(id="x", ok=False, severity="warning", detail="look at this")
    gate = result("G3", [warning])
    assert gate.status == "pass" and gate.blocking_reasons == []


def test_an_error_with_a_waiver_is_waived_and_one_without_blocks() -> None:
    waived = Check(id="x", ok=False, severity="error", detail="a", waiver=waiver("line:1"))
    open_ = Check(id="x", ok=False, severity="error", detail="b")
    assert result("G2", [waived]).status == "waived"
    mixed = result("G2", [waived, open_])
    assert mixed.status == "fail" and mixed.blocking_reasons == ["b"]


def test_a_waiver_that_expires_today_is_valid_and_yesterday_is_expired() -> None:
    assert find_waiver([waiver("line:7", TODAY)], "line:7", TODAY)[0] is not None
    found, note = find_waiver([waiver("line:7", TODAY - timedelta(days=1))], "line:7", TODAY)
    assert found is None and "expired on 2026-11-20" in note
    assert find_waiver([waiver("line:8")], "line:7", TODAY) == (None, "")


def test_the_latest_valid_waiver_is_used() -> None:
    later = waiver("line:7", TODAY + timedelta(days=30))
    found, _ = find_waiver([waiver("line:7"), later], "line:7", TODAY)
    assert found == later


# -- G1 input integrity ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "dialect"),
    [("pix-2006-hq.cfg", Dialect.pix), ("asa-8.2-branch.cfg", Dialect.asa),
     ("ios-12-edge.cfg", Dialect.ios)],
)  # fmt: skip
def test_g1_passes_for_supported_samples_with_an_explicit_dialect(
    name: str, dialect: Dialect
) -> None:
    gate = gate_g1(sample(name, dialect))
    assert gate.status == "pass", gate.blocking_reasons
    assert [c.id for c in gate.checks] == ["g1-sha256", "g1-confidence", "g1-os-version", "g1-mode"]


def test_g1_fails_without_an_input_hash(asa82: Policy) -> None:
    gate = gate_g1(asa82.model_copy(update={"input_sha256": ""}))
    assert gate.status == "fail" and [c.id for c in failing(gate.checks)] == ["g1-sha256"]


@pytest.mark.parametrize(("confidence", "status"), [(0.9, "pass"), (0.899, "fail"), (0.0, "fail")])
def test_g1_needs_a_detection_confidence_of_at_least_0_9(
    asa82: Policy, confidence: float, status: str
) -> None:
    gate = gate_g1(asa82.model_copy(update={"detection_confidence": confidence}))
    assert gate.status == status
    if status == "fail":
        assert "below 0.9" in gate.blocking_reasons[0]


def test_g1_passes_on_the_auto_detected_pix_sample() -> None:
    """Its PIX Version banner agrees with the syntax, so detection gives at least 0.95."""
    policy = parse_config((SAMPLES / "pix-2006-hq.cfg").read_text(encoding="utf-8"))
    assert policy.detection_confidence >= 0.95
    assert gate_g1(policy).status == "pass"


@pytest.mark.parametrize(
    ("dialect", "version", "supported"),
    [
        (Dialect.pix, "6.3(5)", True),
        (Dialect.pix, "6.0(1)", True),
        (Dialect.pix, "7.0(1)", False),
        (Dialect.asa, "7.0(1)", True),
        (Dialect.asa, "8.2(5)", True),
        (Dialect.asa, "8.3(1)", False),
        (Dialect.asa, "9.8(4)", False),
        (Dialect.asa, "6.3(5)", False),
        (Dialect.ios, "12.4", True),
        (Dialect.ios, "12.0(5)T", True),
        (Dialect.ios, "15.1", False),
        (Dialect.ios, "", False),
        (Dialect.panos, "10.1", False),
    ],
)
def test_g1_supports_pix_6_asa_7_0_to_8_2_and_ios_12_only(
    asa82: Policy, dialect: Dialect, version: str, supported: bool
) -> None:
    policy = asa82.model_copy(update={"dialect": dialect, "os_version": version})
    gate = gate_g1(policy)
    assert gate.status == ("pass" if supported else "fail")
    if not supported:
        assert [c.id for c in failing(gate.checks)] == ["g1-os-version"]


@pytest.mark.parametrize("mode", [PolicyMode.transparent, PolicyMode.multiple, PolicyMode.unknown])
def test_g1_fails_outside_routed_single_context_mode(asa82: Policy, mode: PolicyMode) -> None:
    gate = gate_g1(asa82.model_copy(update={"mode": mode}))
    assert gate.status == "fail" and [c.id for c in failing(gate.checks)] == ["g1-mode"]
    assert mode.value in gate.blocking_reasons[0]


# -- G2 coverage -------------------------------------------------------------------------------


def with_records(policy: Policy, *records: LineRecord) -> Policy:
    return policy.model_copy(update={"line_records": [*policy.line_records, *records]})


UNPARSED = LineRecord(line_no=900, text="<redacted>", classification="unparsed",
                      security_relevant=True, reason="non-contiguous-wildcard")  # fmt: skip
OUT_OF_SCOPE = LineRecord(line_no=901, text="<redacted>", classification="out-of-scope",
                          security_relevant=True, reason="identity-firewall")  # fmt: skip


def test_g2_passes_when_every_security_relevant_line_is_handled(
    asa82: Policy, emission: PanosEmission
) -> None:
    gate = gate_g2(asa82, emission, NO_SIDECAR, TODAY)
    assert gate.status == "pass"
    assert [c.id for c in gate.checks] == ["g2-coverage"]


@pytest.mark.parametrize("record", [UNPARSED, OUT_OF_SCOPE])
def test_g2_fails_on_an_unwaived_security_relevant_line(
    asa82: Policy, emission: PanosEmission, record: LineRecord
) -> None:
    gate = gate_g2(with_records(asa82, record), emission, NO_SIDECAR, TODAY)
    assert gate.status == "fail"
    assert gate.blocking_reasons == [
        f"line {record.line_no} is security-relevant and {record.classification} ({record.reason})"
    ]


def test_g2_ignores_lines_that_are_not_security_relevant(
    asa82: Policy, emission: PanosEmission
) -> None:
    quiet = UNPARSED.model_copy(update={"security_relevant": False})
    assert gate_g2(with_records(asa82, quiet), emission, NO_SIDECAR, TODAY).status == "pass"


def test_g2_is_waived_by_a_valid_line_waiver(asa82: Policy, emission: PanosEmission) -> None:
    sidecar = Sidecar(waivers=[waiver("line:900")])
    gate = gate_g2(with_records(asa82, UNPARSED), emission, sidecar, TODAY)
    assert gate.status == "waived" and gate.blocking_reasons == []
    assert failing(gate.checks)[0].waiver == waiver("line:900")


def test_g2_an_expired_or_mismatched_waiver_counts_as_missing(
    asa82: Policy, emission: PanosEmission
) -> None:
    policy = with_records(asa82, UNPARSED)
    expired = Sidecar(waivers=[waiver("line:900", TODAY - timedelta(days=1))])
    gate = gate_g2(policy, emission, expired, TODAY)
    assert gate.status == "fail" and "expired on 2026-11-20" in gate.blocking_reasons[0]
    other = Sidecar(waivers=[waiver("line:899"), waiver("ledger:900")])
    assert gate_g2(policy, emission, other, TODAY).status == "fail"


def test_g2_reads_policy_unparsed_when_there_are_no_line_records(asa82: Policy) -> None:
    bare = asa82.model_copy(
        update={
            "line_records": [],
            "unparsed": [UnparsedLine(line_no=5, text="<redacted>", reason="fqdn-object")],
        }
    )
    gate = gate_g2(bare, None, NO_SIDECAR, TODAY)
    assert gate.status == "fail" and "line 5" in gate.blocking_reasons[0]


def test_g2_blocks_what_the_emitter_could_not_express(
    asa82: Policy, emission: PanosEmission
) -> None:
    unsupported = ["line 41: management access 'x' has no PAN-OS interface-management service"]
    unsupported.append("Static NAT of a subnet or range: 192.0.2.0/28 (mapped)")
    broken = dataclasses.replace(emission, unsupported=unsupported)
    gate = gate_g2(asa82, broken, NO_SIDECAR, TODAY)
    assert gate.status == "fail" and len(gate.blocking_reasons) == 2
    waived_line = gate_g2(asa82, broken, Sidecar(waivers=[waiver("line:41")]), TODAY)
    assert waived_line.status == "fail"
    assert waived_line.blocking_reasons == [f"not expressed in PAN-OS: {unsupported[1]}"]
    only_line = dataclasses.replace(emission, unsupported=unsupported[:1])
    assert gate_g2(asa82, only_line, Sidecar(waivers=[waiver("line:41")]), TODAY).status == (
        "waived"
    )


def test_g2_fails_on_the_asa_9_sample() -> None:
    policy = sample("asa-9.8-dc.cfg", Dialect.asa)
    gate = gate_g2(policy, emit_panos(policy), NO_SIDECAR, TODAY)
    assert gate.status == "fail" and gate.blocking_reasons


# -- G5 ledger review --------------------------------------------------------------------------


def entry(
    entry_id: str, cls: LedgerClass = LedgerClass.to_the_box, **update: object
) -> LedgerEntry:
    base = LedgerEntry(id=entry_id, entry_class=cls, reason="r", affected="a", context="any",
                       old_action=Action.permit, new_action=Action.deny)  # fmt: skip
    return base.model_copy(update=update)


def decided(approval: Approval) -> ApprovalDecision:
    return ApprovalDecision(approval=approval, approver="Sam Approver", decided_at="2026-11-20")


ACCEPTED = {"approval": Approval.accepted, "approver": "Sam Approver", "decided_at": "2026-11-20"}
REJECTED = {"approval": Approval.rejected, "approver": "Sam Approver", "decided_at": "2026-11-20"}


def test_g5_passes_when_every_entry_is_accepted() -> None:
    gate = gate_g5(
        [entry("LED-0001", **ACCEPTED), entry("LED-0002", **ACCEPTED)], NO_SIDECAR, TODAY
    )
    assert gate.status == "pass"
    assert gate.checks[0].detail == "LED-0001 (to-the-box) accepted by Sam Approver"


def test_g5_passes_on_an_empty_ledger() -> None:
    assert gate_g5([], NO_SIDECAR, TODAY).status == "pass"


def test_g5_fails_on_a_pending_entry_including_informational_ones() -> None:
    gate = gate_g5([entry("LED-0001", informational=True)], NO_SIDECAR, TODAY)
    assert gate.status == "fail"
    assert gate.blocking_reasons == ["LED-0001 (to-the-box) is pending a decision"]


def test_g5_fails_on_the_emitted_sample_ledger(emission: PanosEmission) -> None:
    gate = gate_g5(emission.ledger, NO_SIDECAR, TODAY)
    assert gate.status == "fail" and len(gate.blocking_reasons) == len(emission.ledger)


def test_g5_a_sidecar_decision_overrides_the_entry_state() -> None:
    sidecar = Sidecar(ledger_decisions={"LED-0001": decided(Approval.accepted)})
    assert gate_g5([entry("LED-0001")], sidecar, TODAY).status == "pass"


def test_g5_a_pending_entry_with_a_valid_ledger_waiver_is_waived() -> None:
    gate = gate_g5([entry("LED-0001")], Sidecar(waivers=[waiver("ledger:LED-0001")]), TODAY)
    assert gate.status == "waived"
    expired = Sidecar(waivers=[waiver("ledger:LED-0001", TODAY - timedelta(days=1))])
    assert gate_g5([entry("LED-0001")], expired, TODAY).status == "fail"


def test_g5_a_rejected_tightening_that_was_not_applied_passes() -> None:
    gate = gate_g5([entry("TGT-0001", LedgerClass.tightening, **REJECTED)], NO_SIDECAR, TODAY)
    assert gate.status == "pass" and "not applied" in gate.checks[0].detail


def test_g5_a_rejection_after_the_candidate_was_built_fails() -> None:
    sidecar = Sidecar(ledger_decisions={"TGT-0001": decided(Approval.rejected)})
    gate = gate_g5([entry("TGT-0001", LedgerClass.tightening)], sidecar, TODAY)
    assert gate.status == "fail" and "built with it applied" in gate.blocking_reasons[0]


def test_g5_a_rejected_like_for_like_entry_fails() -> None:
    gate = gate_g5([entry("LED-0001", **REJECTED)], NO_SIDECAR, TODAY)
    assert gate.status == "fail" and "still has it" in gate.blocking_reasons[0]


def test_g5_a_decision_for_an_unknown_entry_is_a_warning() -> None:
    sidecar = Sidecar(ledger_decisions={"LED-0099": decided(Approval.accepted)})
    gate = gate_g5([entry("LED-0001", **ACCEPTED)], sidecar, TODAY)
    assert gate.status == "pass"
    assert [c.id for c in failing(gate.checks)] == ["g5-unknown-decision"]


# -- G6 risk findings --------------------------------------------------------------------------


def finding(finding_id: str, severity: Severity) -> Finding:
    kind = FindingType.insecure_service
    return Finding(id=finding_id, type=kind, severity=severity, rule_ref="outside_in#5",
                   explanation="e", recommendation="r", label="l")  # fmt: skip


def test_g6_passes_without_critical_findings() -> None:
    gate = gate_g6([finding("AUT-0001", Severity.high)], NO_SIDECAR, TODAY)
    assert gate.status == "pass" and gate.checks[0].detail == "no critical findings"


def test_g6_fails_on_an_open_critical_finding() -> None:
    gate = gate_g6([finding("AUT-0001", Severity.critical)], NO_SIDECAR, TODAY)
    assert gate.status == "fail"
    assert gate.blocking_reasons == ["critical finding AUT-0001: insecure-service at outside_in#5"]


def test_g6_an_accepted_risk_waives_a_critical_finding_until_it_expires() -> None:
    findings = [finding("AUT-0001", Severity.critical)]
    valid = Sidecar(accepted_risks=[waiver("finding:AUT-0001")])
    gate = gate_g6(findings, valid, TODAY)
    assert gate.status == "waived" and gate.checks[0].waiver == waiver("finding:AUT-0001")
    expired = Sidecar(accepted_risks=[waiver("finding:AUT-0001", TODAY - timedelta(days=1))])
    gate = gate_g6(findings, expired, TODAY)
    assert gate.status == "fail" and "expired on 2026-11-20" in gate.blocking_reasons[0]


def test_g6_a_finding_waiver_is_not_an_accepted_risk() -> None:
    findings = [finding("AUT-0001", Severity.critical)]
    gate = gate_g6(findings, Sidecar(waivers=[waiver("finding:AUT-0001")]), TODAY)
    assert gate.status == "fail"
    assert "g6-waiver-not-risk" in [c.id for c in failing(gate.checks)]


def test_g6_an_accepted_risk_for_an_unknown_finding_is_a_warning() -> None:
    gate = gate_g6([], Sidecar(accepted_risks=[waiver("finding:AUT-0042")]), TODAY)
    assert gate.status == "pass"
    assert [c.id for c in failing(gate.checks)] == ["g6-unknown-risk"]
