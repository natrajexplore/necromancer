"""Zero-trust tightening and its exorcism ledger (requirement 5, property P6).

Tightening is a separate change from the like-for-like migration (governance R1). It starts from
the same parsed ``Policy`` and the autopsy findings, applies the remediations a human chose per
finding, and returns a new ``Policy`` plus a ledger. The baseline policy is never modified, and the
tightened PAN-OS config is emitted from the new policy as its own artifact.

Three remediations change rules, and each can only remove access:

* ``remove-rule``: drop a shadowed or redundant rule. Re-checked against the policy as it stands
  after earlier removals, because two rules can each look redundant because of the other.
* ``replace-service``: remove telnet (23), ftp (21) or http (80) from a permit rule. The secure
  alternative (ssh, sftp over ssh, https) is named in the ledger but never granted: adding it
  would allow flows that were denied before, which breaks monotonicity.
* ``narrow-any``: intersect the source or destination of a permit rule with networks the user
  confirmed. The intersection means a wrong answer can only narrow further, never widen.

Management-plane findings (telnet, http server, SNMP v1/v2c) get an ``advise`` note only.

Every step is assessed with exact box algebra (``necro.tighten_regions``). A step that would permit
any flow the baseline denied is refused, so P6 holds by construction. A step that changes decisions
gets a ``tightening`` ledger entry per affected context whose region is the exact set of flows that
turn from permit to deny. A step that changes no decision gets an informational entry. Entries
start ``pending``. A rejected entry stays in the ledger but its change is not applied.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, field_validator, model_validator

from necro.autopsy import hygiene_findings
from necro.contexts import build_contexts
from necro.emitters.panos import PanosEmission, emit_panos
from necro.findings import Finding, FindingType
from necro.ir import Action, LedgerClass, Policy, Rule
from necro.ledger import Approval, LedgerEntry, make_entry
from necro.sets import AddrSet, PortSet
from necro.tighten_regions import affected_contexts, narrowed, permit_region, widened


class RemediationKind(StrEnum):
    remove_rule = "remove-rule"
    replace_service = "replace-service"
    narrow_any = "narrow-any"
    advise = "advise"  # a note only: management-plane findings change no security rule


_OFFERED = {
    FindingType.shadowed: RemediationKind.remove_rule,
    FindingType.redundant: RemediationKind.remove_rule,
    FindingType.insecure_service: RemediationKind.replace_service,
    FindingType.overly_broad: RemediationKind.narrow_any,
    FindingType.insecure_management: RemediationKind.advise,
}

# insecure TCP port -> (insecure name, secure alternative, alternative port)
_SECURE_ALTERNATIVES = {
    23: ("telnet", "ssh", 22),
    21: ("ftp", "sftp over ssh", 22),
    80: ("http", "https", 443),
}


class Option(BaseModel):
    """One remediation offered for one finding."""

    finding_id: str
    kind: RemediationKind
    rule_ref: str
    summary: str


class Choice(BaseModel):
    """The remediation a user selected for one finding."""

    finding_id: str
    kind: RemediationKind | None = None  # defaults to the one offered for the finding type
    side: Literal["src", "dst"] = "dst"  # narrow-any only
    networks: list[str] = []  # narrow-any only: the networks the user confirms

    @field_validator("networks")
    @classmethod
    def _valid_networks(cls, value: list[str]) -> list[str]:
        for item in value:
            net = ipaddress.ip_network(item, strict=True)
            if net.version != 4:
                raise ValueError(f"only IPv4 networks are supported: {item}")
        return value


class ApprovalDecision(BaseModel):
    """A human decision on the ledger entries of one finding."""

    approval: Approval
    approver: str = ""
    decided_at: str = ""

    @model_validator(mode="after")
    def _named_human(self) -> ApprovalDecision:
        if self.approval != Approval.pending and not (self.approver and self.decided_at):
            raise ValueError("an accepted or rejected entry needs an approver and a decided_at")
        return self


class Skipped(BaseModel):
    finding_id: str
    reason: str


@dataclass
class TightenResult:
    policy: Policy  # the tightened policy (the baseline is untouched)
    ledger: list[LedgerEntry]  # ids TGT-0001...
    applied: list[str]  # finding ids whose change is in ``policy``
    skipped: list[Skipped]
    notes: list[str]  # advisories that change no rule


@dataclass
class TightenedArtifact:
    """The tightened PAN-OS candidate, kept apart from the baseline (governance R1)."""

    result: TightenResult
    emission: PanosEmission

    @property
    def ledger(self) -> list[LedgerEntry]:
        """Tightening entries plus the emitter's own like-for-like entries for this config."""
        return [*self.result.ledger, *self.emission.ledger]


def offer_remediations(findings: list[Finding]) -> list[Option]:
    """The remediation choices for each finding, in finding order."""
    options: list[Option] = []
    for f in findings:
        kind = _OFFERED.get(f.type)
        if kind is not None:
            options.append(
                Option(finding_id=f.id, kind=kind, rule_ref=f.rule_ref, summary=f.recommendation)
            )
    return options


# ---------------------------------------------------------------------------
# Planning: build the changed policy for one finding
# ---------------------------------------------------------------------------


@dataclass
class _Plan:
    after: Policy
    acl: str
    rule: Rule
    reason: str


def _locate(policy: Policy, rule_ref: str) -> tuple[str, int] | None:
    for acl, rules in policy.acls.items():
        for index, rule in enumerate(rules):
            if rule.id == rule_ref:
                return acl, index
    return None


def _replace_at(policy: Policy, acl: str, index: int, rule: Rule | None) -> Policy:
    """A copy of ``policy`` with one rule replaced, or removed when ``rule`` is None."""
    rules = list(policy.acls[acl])
    if rule is None:
        del rules[index]
    else:
        rules[index] = rule
    return policy.model_copy(update={"acls": {**policy.acls, acl: rules}})


def _plan_removal(
    policy: Policy, acl: str, index: int, rule: Rule, finding: Finding
) -> _Plan | str:
    still_ghost = {(f.rule_ref, f.type) for f in hygiene_findings(policy, acl, policy.acls[acl])}
    if (rule.id, finding.type) not in still_ghost:
        return "no longer shadowed or redundant after earlier removals"
    why = "shadowed" if finding.type == FindingType.shadowed else "redundant"
    reason = f"Rule {rule.id} is {why} and was removed. {finding.explanation}"
    return _Plan(_replace_at(policy, acl, index, None), acl, rule, reason)


def _plan_replacement(policy: Policy, acl: str, index: int, rule: Rule) -> _Plan | str:
    ports = rule.match.dst_ports
    if rule.match.proto != 6 or ports == PortSet.any():
        return "the rule does not name specific TCP ports"
    found = [p for p in sorted(_SECURE_ALTERNATIVES) if ports.contains(p)]
    if not found:
        return "no telnet, ftp or http port in the rule"
    left = ports.subtract(PortSet([(p, p) for p in found]))
    parts = []
    for p in found:
        name, alt, alt_port = _SECURE_ALTERNATIVES[p]
        parts.append(f"{name} ({p}/tcp) instead of {alt} ({alt_port}/tcp)")
    reason = (
        f"Insecure service removed from {rule.id}: {'; '.join(parts)}. The secure alternative "
        "is not granted, because tightening never adds access. Request it as a separate change."
    )
    new_rule = (
        None
        if left.is_empty()
        else rule.model_copy(update={"match": rule.match.model_copy(update={"dst_ports": left})})
    )
    return _Plan(_replace_at(policy, acl, index, new_rule), acl, rule, reason)


def _plan_narrowing(
    policy: Policy, acl: str, index: int, rule: Rule, choice: Choice
) -> _Plan | str:
    if not choice.networks:
        return "no confirmed networks were given"
    confirmed = AddrSet.from_cidr_list([ipaddress.IPv4Network(n) for n in choice.networks])
    current = rule.match.src if choice.side == "src" else rule.match.dst
    reduced = current.intersect(confirmed)
    if reduced == current:
        return "the rule is already within the confirmed networks"
    new_rule = (
        None
        if reduced.is_empty()
        else rule.model_copy(update={"match": rule.match.model_copy(update={choice.side: reduced})})
    )
    side = "source" if choice.side == "src" else "destination"
    reason = (
        f"The {side} of {rule.id} was narrowed to the confirmed networks "
        f"{', '.join(choice.networks)}."
    )
    return _Plan(_replace_at(policy, acl, index, new_rule), acl, rule, reason)


def _plan(policy: Policy, finding: Finding, choice: Choice, kind: RemediationKind) -> _Plan | str:
    where = _locate(policy, finding.rule_ref)
    if where is None:
        return "the rule is no longer present"
    acl, index = where
    if acl in policy.egress_acls.values():
        return "ACLs bound outbound are not tightened in v1"
    rule = policy.acls[acl][index]
    if kind == RemediationKind.remove_rule:
        return _plan_removal(policy, acl, index, rule, finding)
    if rule.action != Action.permit:
        return "only permit rules are tightened"
    if kind == RemediationKind.replace_service:
        return _plan_replacement(policy, acl, index, rule)
    return _plan_narrowing(policy, acl, index, rule, choice)


# ---------------------------------------------------------------------------
# Assessment: the exact decision change, and the P6 guard
# ---------------------------------------------------------------------------


def _assess(before: Policy, plan: _Plan, finding_id: str) -> list[LedgerEntry] | str:
    """Ledger entries for the step. A string means the step is refused (it would widen access)."""
    entries: list[LedgerEntry] = []
    for ctx in affected_contexts(build_contexts(before), plan.acl):
        was, now = permit_region(before, ctx), permit_region(plan.after, ctx)
        if widened(was, now):
            return f"it would permit flows that {ctx.name} denied before (breaks P6)"
        lost = narrowed(was, now)
        if lost:
            entries.append(
                make_entry(
                    LedgerClass.tightening,
                    plan.reason,
                    ctx.name,
                    Action.permit,
                    Action.deny,
                    lost,
                    finding_ref=finding_id,
                )
            )
    if entries:
        return entries
    note = make_entry(
        LedgerClass.tightening,
        plan.reason,
        "any",
        plan.rule.action,
        plan.rule.action,
        [],
        informational=True,
        finding_ref=finding_id,
    )
    return [note.model_copy(update={"affected": "no flow changes decision"})]


def _decided(entry: LedgerEntry, decision: ApprovalDecision | None) -> LedgerEntry:
    if decision is None:
        return entry
    return entry.model_copy(
        update={
            "approval": decision.approval,
            "approver": decision.approver,
            "decided_at": decision.decided_at,
        }
    )


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def _index_choices(choices: list[Choice]) -> dict[str, Choice]:
    by_id: dict[str, Choice] = {}
    for choice in choices:
        if choice.finding_id in by_id:
            raise ValueError(f"two choices for finding {choice.finding_id}")
        by_id[choice.finding_id] = choice
    return by_id


def tighten(
    policy: Policy,
    findings: list[Finding],
    choices: list[Choice],
    approvals: dict[str, ApprovalDecision] | None = None,
) -> TightenResult:
    """Apply the chosen remediations. ``policy`` is never modified.

    ``approvals`` maps a finding id to the human decision on its ledger entries. A rejected step
    keeps its (rejected) entries but is not applied. Pending and accepted steps are applied.
    """
    by_id = _index_choices(choices)
    decisions = approvals or {}
    unknown = sorted((set(decisions) | set(by_id)) - {f.id for f in findings})
    if unknown:
        raise ValueError(f"unknown finding id(s): {', '.join(unknown)}")

    current = policy
    ledger: list[LedgerEntry] = []
    applied: list[str] = []
    skipped: list[Skipped] = []
    notes: list[str] = []
    for finding in findings:
        choice = by_id.get(finding.id)
        if choice is None:
            continue
        offered = _OFFERED.get(finding.type)
        kind = choice.kind or offered
        if offered is None or kind != offered:
            skipped.append(Skipped(finding_id=finding.id, reason="not offered for this finding"))
            continue
        if kind == RemediationKind.advise:
            notes.append(f"{finding.id} {finding.rule_ref}: {finding.recommendation}")
            continue
        planned = _plan(current, finding, choice, kind)
        if isinstance(planned, str):
            skipped.append(Skipped(finding_id=finding.id, reason=planned))
            continue
        assessed = _assess(current, planned, finding.id)
        if isinstance(assessed, str):
            skipped.append(Skipped(finding_id=finding.id, reason=assessed))
            continue
        decision = decisions.get(finding.id)
        ledger += [_decided(e, decision) for e in assessed]
        if decision is None or decision.approval != Approval.rejected:
            current = planned.after
            applied.append(finding.id)
    numbered = [e.model_copy(update={"id": f"TGT-{n:04d}"}) for n, e in enumerate(ledger, 1)]
    return TightenResult(current, numbered, applied, skipped, notes)


def resurrect_tightened(
    policy: Policy,
    findings: list[Finding],
    choices: list[Choice],
    approvals: dict[str, ApprovalDecision] | None = None,
) -> TightenedArtifact:
    """Tighten, then emit the PAN-OS candidate for the tightened policy as its own artifact."""
    result = tighten(policy, findings, choices, approvals)
    return TightenedArtifact(result, emit_panos(result.policy))
