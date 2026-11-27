"""Grimoire sections 1 to 3: the verdict page, the audit header, and scope and assumptions.

Wording rule: the report says what the evidence supports and nothing stronger. The verdict page
states that a named human decides.
"""

from __future__ import annotations

from necro.assessment import Assessment
from necro.controls import SECRET_ROTATION_NOTE
from necro.findings import Severity
from necro.gate_models import ChangeMeta, Verdict
from necro.ir import AddressSpace, Dialect, PolicyMode
from necro.report_doc import Block, Bullets, Heading, Para, Section, Table

GATE_NAMES = {
    "G1": "Input integrity",
    "G2": "Coverage",
    "G3": "Target static validation",
    "G4": "Equivalence",
    "G5": "Ledger review",
    "G6": "Risk findings",
}
TIME_MASK = "(not part of the report body)"
NOT_RECORDED = "not recorded"
EVIDENCED = "Evidenced by the tool"
EVIDENCED_OWED = "Evidenced; a human step is owed"
OWED = "Owed by a human"
NOT_EVIDENCED = "Not evidenced"

_ADDRESS_SPACE_TEXT = {
    AddressSpace.mapped: (
        "The ACLs of this config are written with mapped (global) addresses (PIX 6.x and ASA up "
        "to 8.2). The candidate keeps the ACL address, because PAN-OS rules match the pre-NAT "
        "destination, and takes the destination zone from the real address."
    ),
    AddressSpace.real: (
        "The ACLs of this config are written with real addresses (ASA 8.3 and later). A PAN-OS "
        "rule must match the mapped address for flows that arrive on the NAT's mapped interface."
    ),
    AddressSpace.as_is: (
        "The ACLs of this config are applied as written, with no address translation (IOS)."
    ),
}


def _warnings(verdict: Verdict) -> list[str]:
    """Warning details across the gates, each prefixed with its gate."""
    return [
        f"{gate.gate}: {check.detail}"
        for gate in verdict.gates
        for check in gate.checks
        if not check.ok and check.severity == "warning"
    ]


def _bullets_or_none(items: list[str]) -> Block:
    return Bullets(tuple(items)) if items else Para("None.")


def _gate_rows(verdict: Verdict) -> tuple[tuple[str, ...], ...]:
    rows = []
    for gate in verdict.gates:
        warnings = sum(1 for c in gate.checks if not c.ok and c.severity == "warning")
        waived = sum(1 for c in gate.checks if not c.ok and c.severity == "error" and c.waiver)
        if gate.status == "fail":
            detail = f"{len(gate.blocking_reasons)} blocking reason(s)"
        elif gate.status == "waived":
            detail = f"{waived} waived"
        else:
            detail = f"{warnings} warning(s)" if warnings else "all checks pass"
        rows.append((gate.gate, GATE_NAMES[gate.gate], gate.status, detail))
    return tuple(rows)


def _change_rows(change: ChangeMeta) -> tuple[tuple[str, str], ...]:
    def show(value: object) -> str:
        return NOT_RECORDED if value in (None, "") else str(value)

    start = change.window_start.isoformat() if change.window_start else None
    end = change.window_end.isoformat() if change.window_end else None
    return (
        ("Change ID", show(change.change_id)),
        ("Requested by", show(change.requested_by)),
        ("Peer reviewer", show(change.peer_reviewer)),
        ("CAB approval reference", show(change.cab_reference)),
        ("Window start", show(start)),
        ("Window end", show(end)),
    )


def phase_rows(a: Assessment) -> list[tuple[str, str, str, str]]:
    """(phase, name, status, detail) for P0 to P11: what the tool evidences and what is owed."""
    core, change, runbook = a.core, a.sidecar.change, a.runbook
    policy, tightened = core.policy, a.tightened
    serious = [f for f in core.findings if f.severity in (Severity.critical, Severity.high)]
    decided = sum(1 for r in a.sidecar.accepted_risks if r.valid_on(a.today))
    missing = [
        label
        for label, value in (
            ("change ID", change.change_id),
            ("peer reviewer", change.peer_reviewer),
            ("CAB reference", change.cab_reference),
        )
        if not value
    ]
    proof_ok = core.proof is not None and core.proof.passed
    commands = runbook.commands
    p2 = (
        "No critical or high findings."
        if not serious
        else f"{len(serious)} critical or high findings need a decision (fix, accept with an "
        f"expiry, or carry forward); {decided} accepted-risk records are current."
    )
    p3 = (
        f"Candidate of {len(core.emission.lines)} lines with {len(core.emission.ledger)} "
        "ledger entries."
        if proof_ok
        else "The equivalence proof did not pass or did not run."
    )
    p5 = (
        "Not recorded: " + ", ".join(missing) + "."
        if missing
        else "Change ID, peer reviewer and CAB reference are recorded; the reviews are owed."
    )
    p10 = (
        f"A tightened candidate has its own ledger and proof (verdict {tightened.verdict.value})."
        if tightened
        else "No tightening was chosen."
    )
    return [
        (
            "P0",
            "Scope and inventory",
            EVIDENCED_OWED,
            f"Detected {policy.dialect.value} {policy.os_version or 'unknown'}, mode "
            f"{policy.mode.value}, {len(policy.interfaces)} interfaces, {len(policy.acls)} ACLs. "
            "A signed scope with an owner per zone is owed.",
        ),
        (
            "P1",
            "Baseline capture",
            EVIDENCED_OWED,
            "Input SHA-256 is recorded in the audit header. The capture time and the age check "
            "(less than 7 days at cutover) are owed.",
        ),
        ("P2", "Pre-migration hygiene", EVIDENCED if not serious else EVIDENCED_OWED, p2),
        ("P3", "Translation (like-for-like)", EVIDENCED if proof_ok else NOT_EVIDENCED, p3),
        ("P4", "Validation", EVIDENCED, f"Verdict {a.verdict.value} from gates G1 to G6."),
        ("P5", "Peer review and CAB", OWED if missing else EVIDENCED_OWED, p5),
        ("P6", "Pre-cutover checks", OWED, f"{len(runbook.prechecks)} pre-checks are listed."),
        (
            "P7",
            "Cutover",
            OWED,
            f"{len(commands.target)} target commands and {len(commands.source)} source commands "
            f"are listed, plus {len(commands.manual)} manual checks.",
        ),
        (
            "P8",
            "Post-checks and hypercare",
            OWED,
            f"{runbook.hypercare_days} business days; {len(runbook.watch)} items to watch.",
        ),
        (
            "P9",
            "Rollback",
            OWED,
            f"{len(runbook.rollback_triggers)} triggers, a decision limit of "
            f"{runbook.decision_minutes} minutes.",
        ),
        ("P10", "Optimization (separate changes)", EVIDENCED if tightened else "Not started", p10),
        (
            "P11",
            "Decommission",
            OWED,
            f"Record the decommission and rotate the {sum(core.secrets.values())} redacted "
            "secrets.",
        ),
    ]


def verdict_section(a: Assessment) -> Section:
    """Section 1: the verdict, gates, blocking reasons, waivers, change record and phases."""
    verdict = a.verdict
    waivers = tuple(
        (w.target, w.approver, w.expires_on.isoformat(), w.reason) for w in verdict.waivers_used
    )
    blocks: list[Block] = [
        Para(f"Readiness verdict, baseline artifact (like for like): {verdict.value}."),
        Para(
            "This verdict says what the evidence supports. It does not approve the change and it "
            "is not a statement about the change itself. A named human decides."
        ),
        Heading("Gates"),
        Table(("Gate", "Name", "Status", "Detail"), _gate_rows(verdict)),
        Heading("Blocking reasons"),
        _bullets_or_none(verdict.blocking_reasons),
        Heading("Conditions and waivers"),
        _bullets_or_none(verdict.conditions),
        Table(
            ("Target", "Approver", "Expires on", "Reason"),
            waivers,
            empty="No waivers are in use.",
        ),
        Heading("Notes"),
        _bullets_or_none([*verdict.notes, *_warnings(verdict)]),
    ]
    if a.tightened is not None:
        tightened = a.tightened.verdict
        blocks += [
            Heading("Tightened candidate (separate change)"),
            Para(
                f"Readiness verdict, tightened artifact (a separate change): {tightened.value}. "
                "It has its own ledger, proof and findings, and it is never delivered without "
                "that ledger. The baseline verdict above does not depend on it."
            ),
            Table(("Gate", "Name", "Status", "Detail"), _gate_rows(tightened)),
            Heading("Tightened blocking reasons"),
            _bullets_or_none(tightened.blocking_reasons),
            Heading("Tightened conditions"),
            _bullets_or_none([*tightened.conditions, *tightened.notes]),
        ]
    blocks += [
        Heading("Change record"),
        Table(("Field", "Value"), _change_rows(a.sidecar.change)),
        Heading("Governance steps"),
        Table(("Phase", "Step", "Status", "Detail"), tuple(phase_rows(a))),
        Heading("Shared secrets"),
        Para(SECRET_ROTATION_NOTE),
    ]
    return Section(1, "Verdict", tuple(blocks))


def audit_section(a: Assessment, *, mask_time: bool) -> Section:
    """Section 2: the audit header. The UTC time is the only value that differs between runs."""
    audit = a.audit
    stamp = TIME_MASK if mask_time else audit.generated_at.isoformat()
    rows: list[tuple[str, str]] = [
        ("Tool version", audit.tool_version),
        ("Git commit", audit.git_commit),
        ("Generated (UTC)", stamp),
        ("Dialect", audit.dialect),
        ("OS version", audit.os_version),
        *((f"Input SHA-256: {name}", digest) for name, digest in audit.inputs.items()),
        *((f"Option: {name}", value) for name, value in audit.options.items()),
        ("Seed", str(audit.seed)),
        ("Examples per context", str(audit.budget)),
        ("Profile", str(audit.profile)),
        ("Waivers evaluated on", a.today.isoformat()),
        *((f"Output SHA-256: {name}", digest) for name, digest in audit.outputs.items()),
    ]
    return Section(
        2,
        "Audit header",
        (
            Table(("Field", "Value"), tuple(rows)),
            Para(
                "The same input, options and seed give the same report body. Only the generated "
                "time differs."
            ),
        ),
    )


def _scope_rows(a: Assessment) -> tuple[tuple[str, str, str], ...]:
    out_of_scope = a.core.coverage.counts.get("out-of-scope", 0)
    return (
        (
            "Security policy: ACLs bound to interfaces, object groups, security levels",
            "In scope",
            "Migrated like for like",
        ),
        ("Static NAT that maps ACL addresses to zones", "In scope", "Used to find the zone"),
        (
            "Management access to the device (telnet, ssh, http, icmp, snmp)",
            "In scope",
            "Becomes an interface management profile",
        ),
        ("VPN", "Out of scope", "Not migrated by this tool"),
        ("Dynamic routing", "Out of scope", "Not resolved offline"),
        ("AAA", "Out of scope", "Not migrated by this tool"),
        ("IPS and QoS", "Out of scope", "Not migrated by this tool"),
        ("Lines the parser classified as out of scope", "Counted", f"{out_of_scope} lines"),
    )


def scope_section(a: Assessment) -> Section:
    """Section 3: in and out of scope, the address-space model and the zone mapping."""
    policy, emission = a.core.policy, a.core.emission
    ios = policy.dialect == Dialect.ios
    zone_rows = []
    for iface in policy.interfaces:
        if not iface.nameif:
            continue
        zone = emission.zones.by_nameif[iface.nameif]
        zone_rows.append(
            (
                iface.hw_name or iface.nameif,
                iface.nameif,
                "n/a (no security levels)" if ios else str(iface.security_level),
                zone,
                emission.zones.ethernet[zone],
                str(iface.ip_address) if iface.ip_address else "none",
            )
        )
    assumptions = [
        f"Dialect {policy.dialect.value}, OS version {policy.os_version or 'unknown'}, detected "
        f"with confidence {policy.detection_confidence:.3f}.",
        f"Mode: {policy.mode.value}.",
        "Interface ports in the candidate (ethernet1/N) are placeholders, in source interface "
        "order. Mapping them to real ports is a pre-cutover task.",
    ]
    if policy.mode != PolicyMode.routed:
        assumptions.append("This mode is out of scope; the verdict is blocked.")
    if policy.dialect == Dialect.pix or policy.nat_control:
        assumptions.append(
            "nat-control is enforced on the source: a flow with no translation is dropped, "
            "even if an ACL permits it."
        )
    headers = (
        "Interface",
        "Nameif",
        "Security level",
        "PAN-OS zone",
        "Placeholder port",
        "Address",
    )
    return Section(
        3,
        "Scope and assumptions",
        (
            Heading("Scope"),
            Table(("Feature", "Scope", "Treatment"), _scope_rows(a)),
            Heading("Address space"),
            Para(_ADDRESS_SPACE_TEXT[policy.address_space]),
            Bullets(tuple(assumptions)),
            Heading("Zone mapping"),
            Table(headers, tuple(zone_rows)),
        ),
    )
