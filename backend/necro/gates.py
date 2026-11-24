"""Validation gates G1-G6 (requirement 1) over the engine's results and the human sidecar.

Every gate returns a ``GateResult``. A gate fails when an error check is not covered by a valid
waiver, is ``waived`` when every error check is, and passes otherwise. Warnings never block.
``today`` is passed in, so waiver expiry is deterministic: a waiver that expires today is valid.

Waivers by gate: G2 takes ``line:<n>`` waivers, G5 ``ledger:<id>`` waivers and G6 the sidecar's
``accepted_risks``. G1, G3 and G4 are not waivable: a wrong input, an invalid candidate or a
failed proof is fixed, not accepted.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import date
from typing import Literal

from necro.emitters.panos import PanosEmission
from necro.findings import Finding, Severity
from necro.gate_models import Check, GateId, GateResult, Sidecar, Waiver
from necro.ir import Dialect, Flow, LedgerClass, Policy, PolicyMode
from necro.ledger import Approval, LedgerEntry
from necro.proof_types import ContextProof, Counterexample, GoldenResult, ProofResult
from necro.validate_panos import Validation

MIN_CONFIDENCE = 0.9
CI_BUDGET = 5_000  # examples per context; equals necro.oracle.PROFILE_BUDGETS["ci"]
SUPPORTED_OS = "PIX 6.x, ASA 7.0-8.2, IOS 12.x"  # Phase 1; ASA 8.3+ is Phase 2
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^([0-9]+)\.([0-9]+)")
_LINE_PREFIX = re.compile(r"^line ([1-9][0-9]*):")
_BLOCKING_CLASSES = ("unparsed", "out-of-scope")


def _ok(check_id: str, detail: str) -> Check:
    return Check(id=check_id, ok=True, severity="error", detail=detail)


def _error(check_id: str, detail: str, waiver: Waiver | None = None) -> Check:
    return Check(id=check_id, ok=False, severity="error", detail=detail, waiver=waiver)


def _warning(check_id: str, detail: str) -> Check:
    return Check(id=check_id, ok=False, severity="warning", detail=detail)


def result(gate: GateId, checks: Sequence[Check]) -> GateResult:
    """Combine checks into a gate result. Only unwaived errors block."""
    errors = [c for c in checks if not c.ok and c.severity == "error"]
    blocking = [c.detail for c in errors if c.waiver is None]
    status: Literal["pass", "fail", "waived"] = (
        "fail" if blocking else "waived" if errors else "pass"
    )
    return GateResult(gate=gate, status=status, checks=list(checks), blocking_reasons=blocking)


def find_waiver(waivers: Iterable[Waiver], target: str, today: date) -> tuple[Waiver | None, str]:
    """The valid waiver for ``target``, or None plus a note on why none applies (expired)."""
    matching = [w for w in waivers if w.target == target]
    valid = [w for w in matching if w.valid_on(today)]
    if valid:
        return max(valid, key=lambda w: (w.expires_on, w.approver)), ""
    if matching:
        last = max(w.expires_on for w in matching)
        return None, f"; the waiver for {target} expired on {last.isoformat()}"
    return None, ""


# -- G1 input integrity ------------------------------------------------------------------------


def _supported(dialect: Dialect, os_version: str) -> bool:
    match = _VERSION.match(os_version)
    if match is None:
        return False
    version = (int(match.group(1)), int(match.group(2)))
    if dialect == Dialect.pix:
        return version[0] == 6
    if dialect == Dialect.asa:
        return (7, 0) <= version < (8, 3)
    if dialect == Dialect.ios:
        return version[0] == 12
    return False


def gate_g1(policy: Policy) -> GateResult:
    """Input integrity: SHA-256 recorded, dialect confident, OS supported, routed single mode."""
    checks: list[Check] = []
    if _SHA256.match(policy.input_sha256):
        checks.append(_ok("g1-sha256", f"input SHA-256 {policy.input_sha256}"))
    else:
        checks.append(_error("g1-sha256", "the input SHA-256 is not recorded"))
    confidence = f"dialect {policy.dialect.value} detected with confidence "
    confidence += f"{policy.detection_confidence:.3f}"
    if policy.detection_confidence >= MIN_CONFIDENCE:
        checks.append(_ok("g1-confidence", confidence))
    else:
        checks.append(
            _error(
                "g1-confidence",
                f"{confidence}, below {MIN_CONFIDENCE}; state the dialect explicitly "
                "after checking it",
            )
        )
    version = policy.os_version or "unknown"
    os_text = f"{policy.dialect.value} {version}"
    if _supported(policy.dialect, policy.os_version):
        checks.append(_ok("g1-os-version", f"{os_text} is supported ({SUPPORTED_OS})"))
    else:
        checks.append(
            _error("g1-os-version", f"{os_text} is not in the supported list ({SUPPORTED_OS})")
        )
    if policy.mode == PolicyMode.routed:
        checks.append(_ok("g1-mode", "routed, single-context mode"))
    else:
        checks.append(
            _error("g1-mode", f"mode {policy.mode.value} is out of scope (routed single-context)")
        )
    return result("G1", checks)


# -- G2 coverage -------------------------------------------------------------------------------


def _blocking_records(policy: Policy) -> list[tuple[int, str, str]]:
    """(line, classification, reason) of every security-relevant line that was not migrated."""
    if policy.line_records:
        return [
            (r.line_no, r.classification, r.reason or "no reason recorded")
            for r in policy.line_records
            if r.security_relevant and r.classification in _BLOCKING_CLASSES
        ]
    return [(u.line_no, "unparsed", u.reason) for u in policy.unparsed if u.security_relevant]


def gate_g2(
    policy: Policy, emission: PanosEmission | None, sidecar: Sidecar, today: date
) -> GateResult:
    """Coverage: no security-relevant line is unparsed, out of scope or unexpressed unless waived.

    ``emission.unsupported`` lists what the emitter could not express. An item that names a
    source line (``line N: ...``) is waivable with ``line:N``; others are not waivable in v1.
    """
    checks: list[Check] = []
    for line_no, classification, reason in _blocking_records(policy):
        waiver, note = find_waiver(sidecar.waivers, f"line:{line_no}", today)
        detail = f"line {line_no} is security-relevant and {classification} ({reason}){note}"
        checks.append(_error("g2-line", detail, waiver))
    for item in emission.unsupported if emission else []:
        match = _LINE_PREFIX.match(item)
        if match is None:
            checks.append(_error("g2-unsupported", f"not expressed in PAN-OS: {item}"))
            continue
        waiver, note = find_waiver(sidecar.waivers, f"line:{match.group(1)}", today)
        checks.append(_error("g2-unsupported", f"not expressed in PAN-OS: {item}{note}", waiver))
    if not checks:
        relevant = sum(1 for r in policy.line_records if r.security_relevant)
        checks.append(
            _ok("g2-coverage", f"all {relevant} security-relevant lines are migrated or managed")
        )
    return result("G2", checks)


# -- G5 ledger review --------------------------------------------------------------------------


def _review(entry: LedgerEntry, sidecar: Sidecar, today: date) -> Check:
    label = f"{entry.id or 'unnumbered entry'} ({entry.entry_class.value})"
    decision = sidecar.ledger_decisions.get(entry.id)
    approval = decision.approval if decision else entry.approval
    approver = decision.approver if decision else entry.approver
    if approval == Approval.accepted:
        return _ok("g5-entry", f"{label} accepted by {approver}")
    if approval == Approval.pending:
        waiver, note = find_waiver(sidecar.waivers, f"ledger:{entry.id}", today)
        return _error("g5-pending", f"{label} is pending a decision{note}", waiver)
    if entry.approval != Approval.rejected:
        return _error(
            "g5-rejected-applied",
            f"{label} was rejected by {approver}, but the candidate was built with it applied; "
            "re-run with this decision",
        )
    if entry.entry_class == LedgerClass.tightening:
        return _ok("g5-entry", f"{label} rejected by {approver}, so it is not applied")
    return _error(
        "g5-rejected-applied",
        f"{label} was rejected by {approver}, but the like-for-like candidate still has it",
    )


def gate_g5(ledger: Sequence[LedgerEntry], sidecar: Sidecar, today: date) -> GateResult:
    """Ledger review: every entry accepted, or rejected and not in the output."""
    checks = [_review(entry, sidecar, today) for entry in ledger]
    known = {entry.id for entry in ledger}
    for entry_id in sorted(set(sidecar.ledger_decisions) - known):
        checks.append(
            _warning("g5-unknown-decision", f"a decision names {entry_id}, not in the ledger")
        )
    if not ledger:
        checks.append(_ok("g5-entry", "the ledger is empty"))
    return result("G5", checks)


# -- G6 risk findings --------------------------------------------------------------------------


def gate_g6(findings: Sequence[Finding], sidecar: Sidecar, today: date) -> GateResult:
    """Risk findings: no open critical finding without a valid accepted-risk record."""
    checks: list[Check] = []
    critical = [f for f in findings if f.severity == Severity.critical]
    for finding in critical:
        risk, note = find_waiver(sidecar.accepted_risks, f"finding:{finding.id}", today)
        detail = f"critical finding {finding.id}: {finding.type.value} at {finding.rule_ref}{note}"
        checks.append(_error("g6-critical", detail, risk))
    known = {f"finding:{f.id}" for f in findings}
    for risk in sidecar.accepted_risks:
        if risk.target not in known:
            checks.append(
                _warning("g6-unknown-risk", f"an accepted risk names {risk.target}, not a finding")
            )
    for misplaced in sidecar.waivers:
        if misplaced.kind == "finding":
            checks.append(
                _warning(
                    "g6-waiver-not-risk",
                    f"the waiver for {misplaced.target} has no effect; a finding is accepted "
                    "through accepted_risks",
                )
            )
    if not critical:
        checks.append(_ok("g6-critical", "no critical findings"))
    return result("G6", checks)


# -- G3 static validation ----------------------------------------------------------------------


def gate_g3(validation: Validation) -> GateResult:
    """Static validation of the candidate: its errors block, its warnings are listed."""
    return result("G3", validation.checks)


# -- G4 equivalence ----------------------------------------------------------------------------


def _flow_text(flow: Flow) -> str:
    text = f"proto {flow.proto} {flow.src}"
    if flow.proto in (6, 17):
        return f"{text}:{flow.src_port} -> {flow.dst}:{flow.dst_port}"
    if flow.icmp_type is not None:
        return f"{text} -> {flow.dst} icmp-type {flow.icmp_type}"
    return f"{text} -> {flow.dst}"


def _divergence(cx: Counterexample) -> str:
    where = f"golden flow {cx.vector_id}" if cx.vector_id else f"context {cx.context}"
    return (
        f"{where}: {_flow_text(cx.flow)} is {cx.original.action.value} on the source and "
        f"{cx.resurrected.action.value} on the candidate ({cx.reason})"
    )


def _context_checks(context: ContextProof) -> list[Check]:
    checks: list[Check] = []
    name = context.context
    if not context.passed:
        detail = f"context {name}: divergence outside the ledger"
        if context.counterexample is not None:
            detail = _divergence(context.counterexample)
        checks.append(_error("g4-divergence", detail))
    elif context.examples < CI_BUDGET:
        checks.append(
            _error("g4-budget", f"context {name}: {context.examples} examples, below {CI_BUDGET}")
        )
    else:
        checks.append(
            _ok("g4-context", f"context {name}: {context.examples} examples, no divergence")
        )
    for side, cover in (("source", context.original), ("candidate", context.resurrected)):
        if cover.unhit:
            checks.append(
                _warning(
                    "g4-unhit",
                    f"context {name}: {side} rules never hit: {', '.join(cover.unhit)}",
                )
            )
    return checks


def _golden_checks(golden: GoldenResult) -> list[Check]:
    if golden.total == 0:
        return [_warning("g4-golden", "no golden flows were checked for this config")]
    checks = [_error("g4-golden", _divergence(cx)) for cx in golden.failures]
    if golden.passed < golden.total and not checks:
        checks.append(_error("g4-golden", f"{golden.total - golden.passed} golden flows failed"))
    if not checks:
        checks.append(_ok("g4-golden", f"all {golden.total} golden flows pass"))
    return checks


def gate_g4(proof: ProofResult | None, golden: GoldenResult | None = None) -> GateResult:
    """Equivalence: the proof ran at the ``ci`` budget or higher in every context, found no
    divergence outside the ledger, and every golden flow passes. ``golden`` defaults to the
    golden result inside ``proof``. Active rules never hit on either side are warnings."""
    if proof is None:
        return result("G4", [_error("g4-proof", "no equivalence proof was run")])
    checks: list[Check] = []
    if proof.budget < CI_BUDGET:
        checks.append(
            _error(
                "g4-budget",
                f"the proof ran with a budget of {proof.budget} examples per context, "
                f"below the ci budget of {CI_BUDGET}",
            )
        )
    if not proof.contexts:
        checks.append(_error("g4-contexts", "the proof checked no contexts"))
    for context in proof.contexts:
        checks += _context_checks(context)
    checks += _golden_checks(golden if golden is not None else proof.golden)
    blocked = any(not c.ok and c.severity == "error" for c in checks)
    if not proof.passed and not blocked:
        detail = "the proof did not pass"
        if proof.counterexample is not None:
            detail = _divergence(proof.counterexample)
        checks.append(_error("g4-divergence", detail))
    return result("G4", checks)
