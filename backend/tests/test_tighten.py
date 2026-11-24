"""Task 7: zero-trust tightening, the exorcism ledger and property P6 (requirement 5).

P6: tightening is monotone. Any flow permitted after tightening was permitted before. The test
also checks the ledger: every flow whose decision changed lies in a ``tightening`` entry that
declares the new action, so the oracle can compare the tightened artifact modulo the ledger.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from necro.autopsy import analyze
from necro.contexts import build_contexts
from necro.emitters.panos import emit_panos
from necro.evaluate import decide
from necro.findings import Finding, FindingType
from necro.ir import Action, Flow, LedgerClass, Policy
from necro.ledger import Approval, covering
from necro.parsers import parse_config
from necro.parsers.pix_asa import parse_pix_asa
from necro.tighten import (
    ApprovalDecision,
    Choice,
    RemediationKind,
    TightenResult,
    offer_remediations,
    resurrect_tightened,
    tighten,
)
from tests.ir_strategies import flows_near, ios_policies, pix_asa_policies

SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "dead-configs"
SAMPLE_NAMES = ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "asa-9.8-dc.cfg", "ios-12-edge.cfg"]

BASE = """
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
"""
BIND = "access-group A in interface outside\n"


def _policy(acl_lines: str) -> Policy:
    return parse_pix_asa(BASE + acl_lines + BIND)


def _flow(dst_port: int, src: str = "203.0.113.9", dst: str = "10.0.0.50") -> Flow:
    return Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=6,
        src_port=40000,
        dst_port=dst_port,
    )


def _of_type(findings: list[Finding], kind: FindingType) -> list[Finding]:
    return [f for f in findings if f.type == kind]


def _default_choices(findings: list[Finding], networks: list[str]) -> list[Choice]:
    return [
        Choice(finding_id=o.finding_id, networks=networks if o.kind == "narrow-any" else [])
        for o in offer_remediations(findings)
    ]


def check_p6(policy: Policy, result: TightenResult, flows: list[Flow]) -> int:
    """Assert P6 and ledger coverage over ``flows``. Returns how many decisions changed."""
    changed = 0
    for ctx in build_contexts(policy):
        tight_ctx = next(c for c in build_contexts(result.policy) if c.name == ctx.name)
        for flow in flows:
            before = decide(policy, ctx, flow)
            after = decide(result.policy, tight_ctx, flow)
            assert not (after.action == Action.permit and before.action == Action.deny), (
                ctx.name,
                flow,
            )
            if before.action != after.action:
                changed += 1
                hits = [
                    e
                    for e in covering(result.ledger, ctx.name, flow)
                    if e.entry_class == LedgerClass.tightening and e.new_action == after.action
                ]
                assert hits, (ctx.name, flow, before, after)
    return changed


# ---------------------------------------------------------------------------
# Offers and removals
# ---------------------------------------------------------------------------


def test_every_finding_type_with_a_remediation_is_offered() -> None:
    policy = parse_config((SAMPLES / "pix-2006-hq.cfg").read_text(encoding="utf-8"))
    findings = analyze(policy)
    offered = {o.finding_id: o.kind for o in offer_remediations(findings)}
    by_type = {f.type: offered[f.id] for f in findings if f.id in offered}
    assert by_type[FindingType.shadowed] == RemediationKind.remove_rule
    assert by_type[FindingType.redundant] == RemediationKind.remove_rule
    assert FindingType.no_remark not in by_type


def test_removing_a_shadowed_rule_is_informational_and_leaves_the_baseline_alone() -> None:
    policy = _policy(
        "access-list A extended permit ip any any\n"
        "access-list A extended permit tcp any any eq 80\n"
    )
    snapshot = policy.model_copy(deep=True)
    findings = analyze(policy)
    shadowed = _of_type(findings, FindingType.shadowed)[0]
    result = tighten(policy, findings, [Choice(finding_id=shadowed.id)])
    assert policy == snapshot
    assert [r.id for r in result.policy.acls["A"]] == ["A#1"]
    (entry,) = result.ledger
    assert entry.informational and entry.entry_class == LedgerClass.tightening
    assert entry.approval == Approval.pending and entry.finding_ref == shadowed.id
    assert entry.id == "TGT-0001"
    assert result.applied == [shadowed.id]


def test_mutually_redundant_rules_are_not_both_removed() -> None:
    policy = _policy(
        "access-list A extended permit tcp any any eq 80\n"
        "access-list A extended permit tcp any any eq 80\n"
    )
    findings = analyze(policy)
    ghosts = [f for f in findings if f.type in (FindingType.shadowed, FindingType.redundant)]
    assert len(ghosts) == 2
    result = tighten(policy, findings, [Choice(finding_id=f.id) for f in ghosts])
    assert len(result.applied) == 1 and len(result.skipped) == 1
    assert len(result.policy.acls["A"]) == 1
    assert check_p6(policy, result, [_flow(80), _flow(81)]) == 0


# ---------------------------------------------------------------------------
# Insecure services
# ---------------------------------------------------------------------------


def test_telnet_is_removed_with_an_exact_ledger_region_and_no_new_access() -> None:
    policy = _policy("access-list A extended permit tcp any any eq 23\n")
    findings = analyze(policy)
    finding = _of_type(findings, FindingType.insecure_service)[0]
    result = tighten(policy, findings, [Choice(finding_id=finding.id)])
    assert result.policy.acls["A"] == []
    (entry,) = result.ledger
    assert (entry.old_action, entry.new_action) == (Action.permit, Action.deny)
    assert not entry.informational and entry.context == "outside:in"
    assert "ssh (22/tcp)" in entry.reason and "never adds access" in entry.reason
    assert entry.covers("outside:in", _flow(23))
    assert not entry.covers("outside:in", _flow(22))
    ctx = build_contexts(result.policy)[0]
    assert decide(result.policy, ctx, _flow(22)).action == Action.deny  # ssh not granted
    assert check_p6(policy, result, [_flow(21), _flow(22), _flow(23), _flow(24)]) == 1


def test_only_the_insecure_ports_leave_a_mixed_rule() -> None:
    policy = _policy(
        "object-group service MIX tcp\n port-object eq 21\n port-object eq 443\n"
        "access-list A extended permit tcp any any object-group MIX\n"
    )
    findings = analyze(policy)
    (f,) = _of_type(findings, FindingType.insecure_service)
    result = tighten(policy, findings, [Choice(finding_id=f.id)])
    ports = result.policy.acls["A"][0].match.dst_ports
    assert ports.contains(443) and not ports.contains(21)
    assert check_p6(policy, result, [_flow(21), _flow(22), _flow(443)]) == 1


def test_a_range_loses_exactly_the_insecure_ports() -> None:
    policy = _policy("access-list A extended permit tcp any any range 20 25\n")
    findings = analyze(policy)
    f = _of_type(findings, FindingType.insecure_service)[0]
    result = tighten(policy, findings, [Choice(finding_id=f.id)])
    ports = result.policy.acls["A"][0].match.dst_ports
    assert [p for p in range(19, 27) if ports.contains(p)] == [20, 22, 24, 25]


def test_a_udp_rule_has_nothing_to_replace() -> None:
    policy = _policy("access-list A extended permit udp any any eq 69\n")
    findings = analyze(policy)
    f = _of_type(findings, FindingType.insecure_service)[0]
    result = tighten(policy, findings, [Choice(finding_id=f.id)])
    assert result.skipped[0].reason == "the rule does not name specific TCP ports"
    assert result.policy == policy


# ---------------------------------------------------------------------------
# Narrowing any
# ---------------------------------------------------------------------------


def test_narrowing_any_to_confirmed_networks() -> None:
    policy = _policy("access-list A extended permit ip any any\n")
    findings = analyze(policy)
    broad = _of_type(findings, FindingType.overly_broad)[0]
    choice = Choice(finding_id=broad.id, side="dst", networks=["10.0.0.0/24"])
    result = tighten(policy, findings, [choice])
    assert result.policy.acls["A"][0].match.dst.contains(ipaddress.IPv4Address("10.0.0.7"))
    assert not result.policy.acls["A"][0].match.dst.contains(ipaddress.IPv4Address("10.0.1.7"))
    (entry,) = result.ledger
    assert entry.covers("outside:in", _flow(443, dst="10.0.1.7"))
    assert not entry.covers("outside:in", _flow(443, dst="10.0.0.7"))
    assert check_p6(policy, result, [_flow(443, dst=d) for d in ("10.0.0.7", "10.0.1.7")]) == 1


def test_narrowing_cannot_widen_even_with_a_bigger_confirmed_network() -> None:
    policy = _policy("access-list A extended permit ip any 10.0.0.0 255.255.255.0\n")
    findings = analyze(policy)
    broad = _of_type(findings, FindingType.overly_broad)
    choices = [Choice(finding_id=f.id, networks=["10.0.0.0/8"]) for f in broad]
    result = tighten(policy, findings, choices)
    assert not result.policy.acls["A"][0].match.dst.contains(ipaddress.IPv4Address("10.9.9.9"))


def test_narrowing_needs_networks_and_rejects_bad_ones() -> None:
    policy = _policy("access-list A extended permit ip any any\n")
    findings = analyze(policy)
    broad = _of_type(findings, FindingType.overly_broad)[0]
    result = tighten(policy, findings, [Choice(finding_id=broad.id)])
    assert result.skipped[0].reason == "no confirmed networks were given"
    assert result.policy == policy
    with pytest.raises(ValueError):
        Choice(finding_id=broad.id, networks=["10.0.0.1/24"])  # host bits set
    with pytest.raises(ValueError):
        Choice(finding_id=broad.id, networks=["2001:db8::/32"])


# ---------------------------------------------------------------------------
# Approvals, advice, validation
# ---------------------------------------------------------------------------


def test_a_rejected_entry_stays_in_the_ledger_but_is_not_applied() -> None:
    policy = _policy("access-list A extended permit tcp any any eq 23\n")
    findings = analyze(policy)
    f = _of_type(findings, FindingType.insecure_service)[0]
    rejected = ApprovalDecision(approval=Approval.rejected, approver="A. Reviewer", decided_at="x")
    result = tighten(policy, findings, [Choice(finding_id=f.id)], {f.id: rejected})
    assert result.applied == [] and len(result.policy.acls["A"]) == 1
    (entry,) = result.ledger
    assert entry.approval == Approval.rejected and entry.approver == "A. Reviewer"
    accepted = ApprovalDecision(approval=Approval.accepted, approver="A. Reviewer", decided_at="x")
    result = tighten(policy, findings, [Choice(finding_id=f.id)], {f.id: accepted})
    assert result.applied == [f.id] and result.ledger[0].approval == Approval.accepted


def test_a_decision_needs_a_named_approver() -> None:
    with pytest.raises(ValidationError):
        ApprovalDecision(approval=Approval.accepted)
    assert ApprovalDecision(approval=Approval.pending).approver == ""


def test_unknown_and_duplicate_findings_are_input_errors() -> None:
    policy = _policy("access-list A extended permit ip any any\n")
    findings = analyze(policy)
    with pytest.raises(ValueError, match="unknown finding"):
        tighten(policy, findings, [Choice(finding_id="AUT-9999")])
    with pytest.raises(ValueError, match="unknown finding"):
        tighten(policy, findings, [], {"AUT-9999": ApprovalDecision(approval=Approval.pending)})
    first = findings[0].id
    with pytest.raises(ValueError, match="two choices"):
        tighten(policy, findings, [Choice(finding_id=first), Choice(finding_id=first)])


def test_a_choice_that_is_not_offered_is_skipped() -> None:
    policy = _policy("access-list A extended permit tcp any any eq 8080\n")
    findings = analyze(policy)
    remark = _of_type(findings, FindingType.no_remark)[0]
    result = tighten(policy, findings, [Choice(finding_id=remark.id)])
    assert result.skipped[0].reason == "not offered for this finding"
    wrong = tighten(
        policy, findings, [Choice(finding_id=remark.id, kind=RemediationKind.remove_rule)]
    )
    assert wrong.skipped and wrong.policy == policy


def test_management_findings_give_a_note_and_change_no_rule() -> None:
    policy = parse_config((SAMPLES / "pix-2006-hq.cfg").read_text(encoding="utf-8"))
    findings = analyze(policy)
    mgmt = _of_type(findings, FindingType.insecure_management)
    assert mgmt
    result = tighten(policy, findings, [Choice(finding_id=f.id) for f in mgmt])
    assert len(result.notes) == len(mgmt) and result.ledger == []
    assert result.policy.acls == policy.acls


def test_outbound_acls_are_not_tightened() -> None:
    policy = parse_pix_asa(
        BASE + "access-list OUT extended permit tcp any any eq 23\n"
        "access-group OUT out interface inside\n"
    )
    findings = analyze(policy)
    f = _of_type(findings, FindingType.insecure_service)
    result = tighten(policy, findings, [Choice(finding_id=x.id) for x in f])
    assert all("outbound" in s.reason for s in result.skipped)
    assert result.policy.acls == policy.acls


def test_global_acl_fall_through_is_accounted_for() -> None:
    policy = parse_pix_asa(
        BASE.replace("security-level 0", "security-level 0")
        + "access-list A extended permit tcp any any eq 23\n"
        "access-list G extended permit tcp any any eq 23\n" + BIND + "access-group G global\n"
    )
    findings = analyze(policy)
    f = [x for x in _of_type(findings, FindingType.insecure_service) if x.rule_ref == "A#1"]
    result = tighten(policy, findings, [Choice(finding_id=x.id) for x in f])
    # telnet still falls through to the global ACL, so no decision changes
    assert result.ledger and all(e.informational for e in result.ledger)
    assert check_p6(policy, result, [_flow(23)]) == 0


# ---------------------------------------------------------------------------
# Separate artifacts (governance R1)
# ---------------------------------------------------------------------------


def test_baseline_and_tightened_artifacts_are_separate() -> None:
    policy = parse_config((SAMPLES / "pix-2006-hq.cfg").read_text(encoding="utf-8"))
    baseline = emit_panos(policy)
    findings = analyze(policy)
    artifact = resurrect_tightened(policy, findings, _default_choices(findings, ["10.0.0.0/8"]))
    assert emit_panos(policy).text == baseline.text  # the baseline is untouched
    assert artifact.emission.text != baseline.text
    assert artifact.result.policy is not policy
    ids = [e.id for e in artifact.ledger]
    assert len(ids) == len(set(ids))
    assert any(e.entry_class == LedgerClass.tightening for e in artifact.ledger)
    assert all(e.approval == Approval.pending for e in artifact.result.ledger)


def test_tightening_is_deterministic() -> None:
    policy = parse_config((SAMPLES / "asa-8.2-branch.cfg").read_text(encoding="utf-8"))
    findings = analyze(policy)
    choices = _default_choices(findings, ["10.0.0.0/8"])
    first = resurrect_tightened(policy, findings, choices)
    second = resurrect_tightened(policy, findings, choices)
    assert first.emission.text == second.emission.text
    assert [e.model_dump_json(by_alias=True) for e in first.ledger] == [
        e.model_dump_json(by_alias=True) for e in second.ledger
    ]


# ---------------------------------------------------------------------------
# P6
# ---------------------------------------------------------------------------


def _p6(policy: Policy, data: st.DataObject) -> None:
    findings = analyze(policy)
    nets = data.draw(
        st.lists(st.sampled_from(["10.0.0.0/24", "10.1.0.0/16", "192.0.2.0/24"]), max_size=2)
    )
    choices = [
        c
        for c in _default_choices(findings, nets)
        if data.draw(st.booleans()) or not nets  # a random subset of the offered remediations
    ]
    result = tighten(policy, findings, choices)
    matches = [r.match for rules in policy.acls.values() for r in rules]
    flows = data.draw(st.lists(flows_near(matches), min_size=10, max_size=25))
    flows += [_flow(p) for p in (21, 23, 80)]
    changed = check_p6(policy, result, flows)
    event(f"applied={min(len(result.applied), 3)}")
    event(f"changed={'some' if changed else 'none'}")


@pytest.mark.pbt
@settings(deadline=None)  # decide() over a whole policy is slow under coverage
@given(policy=pix_asa_policies(), data=st.data())
def test_p6_tightening_is_monotone_pix_asa(policy: Policy, data: st.DataObject) -> None:
    _p6(policy, data)


@pytest.mark.pbt
@settings(deadline=None)
@given(policy=ios_policies(), data=st.data())
def test_p6_tightening_is_monotone_ios(policy: Policy, data: st.DataObject) -> None:
    _p6(policy, data)


@pytest.mark.pbt
@pytest.mark.parametrize("name", SAMPLE_NAMES)
@settings(deadline=None)
@given(data=st.data())
def test_p6_on_the_samples(name: str, data: st.DataObject) -> None:
    policy = parse_config((SAMPLES / name).read_text(encoding="utf-8"))
    findings = analyze(policy)
    result = tighten(policy, findings, _default_choices(findings, ["10.0.0.0/8"]))
    matches = [r.match for rules in policy.acls.values() for r in rules]
    flows = data.draw(st.lists(flows_near(matches), min_size=20, max_size=40))
    assert check_p6(policy, result, flows) >= 0
    assert result.applied  # the sample ghosts and broad rules are really tightened
