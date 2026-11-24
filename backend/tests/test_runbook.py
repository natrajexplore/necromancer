"""Task 8: the runbook. Commands, ASA version gating, rollback, hypercare and a snapshot per sample.

Snapshots live in ``tests/snapshots``. When the runbook changes on purpose, regenerate them with
``NECRO_UPDATE_SNAPSHOTS=1`` and review the diff: it is the cutover checklist a human will run.
"""

from __future__ import annotations

import os
import re
from functools import cache
from pathlib import Path

import pytest

from necro import runbook_commands
from necro.emitters import PanosEmission, emit_panos
from necro.gate_models import RunbookOverrides, Sidecar, parse_sidecar
from necro.golden import GoldenVector, load_golden
from necro.ir import Dialect, Policy
from necro.oracle import prove
from necro.oracle_core import Sides
from necro.oracle_flows import flow_space
from necro.parsers import parse_config
from necro.proof_types import ProofResult
from necro.runbook import (
    DEFAULT_DECISION_MINUTES,
    DEFAULT_HYPERCARE_DAYS,
    DEFAULT_ROLLBACK_TRIGGERS,
    MAX_COMMANDS,
    Runbook,
    build_commands,
    build_runbook,
    packet_tracer_supported,
)
from necro.runbook_doc import render_runbook_md
from necro.secret_counts import count_secrets

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples" / "dead-configs"
GOLDEN = ROOT / "samples" / "golden-flows"
SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"
DIALECTS = {
    "pix-2006-hq": Dialect.pix,
    "asa-8.2-branch": Dialect.asa,
    "asa-9.8-dc": Dialect.asa,
    "ios-12-edge": Dialect.ios,
}
NAMES = tuple(DIALECTS)
BUDGET = 100
FORBIDDEN = re.compile(r"compliant|safe\s+to\s+deploy", re.IGNORECASE)
IP = r"(\d+\.){3}\d+"
PANOS = re.compile(
    rf"^test security-policy-match from \S+ to \S+ source {IP} destination {IP}"
    r"( destination-port \d+)? protocol \d+( application \S+)?$"
)
TRACER_TCP_UDP = re.compile(rf"^packet-tracer input \S+ (tcp|udp) {IP} \d+ {IP} \d+$")
TRACER_ICMP = re.compile(rf"^packet-tracer input \S+ icmp {IP} \d+ 0 {IP}$")
TRACER_RAW = re.compile(rf"^packet-tracer input \S+ rawip {IP} \d+ {IP}$")


class Built:
    """A sample taken through emit, prove and the runbook, the way the pipeline does."""

    def __init__(self, name: str) -> None:
        text = (SAMPLES / f"{name}.cfg").read_text(encoding="utf-8")
        self.policy: Policy = parse_config(text, DIALECTS[name])
        self.emission: PanosEmission = emit_panos(self.policy)
        self.vectors: list[GoldenVector] = load_golden(GOLDEN / f"{name}.toml")
        self.proof: ProofResult = prove(
            self.policy,
            self.emission.text,
            self.emission.ledger,
            budget=BUDGET,
            seed=7,
            golden=self.vectors,
        )
        self.commands = build_commands(self.policy, self.emission, self.vectors)
        self.secrets = sum(count_secrets(r.text for r in self.policy.line_records).values())
        self.runbook: Runbook = self.build(Sidecar())

    def build(self, sidecar: Sidecar) -> Runbook:
        return build_runbook(
            self.policy,
            self.emission,
            self.commands,
            self.emission.ledger,
            self.proof,
            sidecar,
            secret_total=self.secrets,
        )


@cache
def built(name: str) -> Built:
    return Built(name)


# -- verification commands ---------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_target_commands_have_the_panos_syntax_and_a_result(name: str) -> None:
    b = built(name)
    commands = b.runbook.commands
    assert commands.target
    for item in commands.target:
        assert PANOS.match(item.command), item.command
        assert item.expected.startswith(("allow", "deny")), item.expected
        if b.proof.passed:  # the candidate agrees with every expectation
            assert item.expected.startswith(("allow by rule ", "deny by rule ")), item.expected
            assert "reports as a failure" not in item.expected
        has_ports = re.search(r" protocol (6|17)( |$)", item.command) is not None
        assert ("destination-port" in item.command) == has_ports, item.command
    oracle = [c.command for c in commands.target if c.origin == "oracle"]
    golden = {c.command for c in commands.target if c.origin == "golden"}
    assert len(set(oracle)) == len(oracle) and not set(oracle) & golden  # no repeated command


@pytest.mark.parametrize("name", NAMES)
def test_every_golden_flow_comes_first_and_none_is_lost(name: str) -> None:
    b = built(name)
    commands = b.runbook.commands
    golden_ids = [c.id for c in commands.target if c.origin == "golden"]
    manual_ids = [m.id for m in commands.manual if m.origin == "golden"]
    assert sorted(golden_ids + manual_ids) == sorted(v.id for v in b.vectors)
    assert golden_ids == [v.id for v in b.vectors if v.id in golden_ids]  # file order kept
    origins = [c.origin for c in commands.target]
    assert origins == sorted(origins, key=lambda o: o != "golden")  # golden before oracle


@pytest.mark.parametrize("name", NAMES)
def test_golden_expectations_are_the_hand_verified_ones(name: str) -> None:
    b = built(name)
    by_id = {v.id: v for v in b.vectors}
    for item in b.runbook.commands.target:
        if item.origin != "golden":
            continue
        vector = by_id[item.id]
        if vector.expect_ledger is None:
            want = "allow" if vector.expect_action.value == "permit" else "deny"
            assert item.expected.split(" ", 1)[0].rstrip(";") == want, item
        elif b.proof.passed:
            assert "ledger LED-" in item.expected, item


@pytest.mark.parametrize("name", NAMES)
def test_oracle_flows_reach_every_rule_that_the_sweep_reaches(name: str) -> None:
    """Recomputed independently: every candidate rule that a witness flow hits has a command."""
    b = built(name)
    commands = b.runbook.commands
    assert commands.omitted == 0
    listed = " ".join(c.expected for c in (*commands.target, *commands.manual))
    sides = Sides(b.policy, b.emission.text, b.emission.ledger)
    for ctx in sides.contexts:
        for flow in flow_space(b.policy, ctx).witnesses:
            hit = sides.check(ctx, flow).resurrected.rule_id.split("/", 1)[0]
            assert f"by rule {hit}" in listed, f"{ctx.name}: no command for rule {hit}"


@pytest.mark.parametrize("name", NAMES)
def test_oracle_flows_are_realistic_where_a_realistic_flow_exists(name: str) -> None:
    b = built(name)
    for item in b.runbook.commands.target:
        if item.origin == "oracle":
            assert not re.search(r"(source|destination) 0\.", item.command), item.command
            assert "destination-port 0 " not in item.command, item.command


def test_a_golden_flow_that_the_candidate_contradicts_is_reported_as_such() -> None:
    """ASA 9.8 object NAT is Phase 2: the proof fails, and the runbook must not hide it."""
    b = built("asa-9.8-dc")
    assert not b.proof.passed
    failing = [c for c in b.runbook.commands.target if "reports as a failure" in c.expected]
    assert failing and all(c.origin == "golden" for c in failing)
    by_id = {v.id: v for v in b.vectors}
    for item in failing:
        word = "allow" if by_id[item.id].expect_action.value == "permit" else "deny"
        assert item.expected.startswith(f"{word}; the candidate gives ")


def test_the_commands_are_deterministic() -> None:
    first = Built("ios-12-edge").runbook.model_dump_json()
    assert Built("ios-12-edge").runbook.model_dump_json() == first


def test_the_command_cap_is_applied_and_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    b = built("pix-2006-hq")
    monkeypatch.setattr(runbook_commands, "MAX_COMMANDS", 5)
    capped = build_commands(b.policy, b.emission, b.vectors)
    assert len(capped.target) == 5
    assert capped.omitted == len(b.runbook.commands.target) - 5
    assert MAX_COMMANDS == 200


def test_flows_to_the_device_are_manual_checks_with_a_reason() -> None:
    commands = built("ios-12-edge").runbook.commands
    assert commands.manual and any("management profile" in m.why for m in commands.manual)
    assert all(m.expected and m.flow for m in commands.manual)
    assert not any(" to self " in c.command + " " for c in commands.target)


def test_icmp_commands_name_the_type_and_the_custom_application() -> None:
    commands = built("pix-2006-hq").runbook.commands.target
    icmp = [c for c in commands if re.search(r" protocol 1( |$)", c.command)]
    assert icmp
    assert all("destination-port" not in c.command for c in icmp)
    assert all(c.note.startswith("ICMP type") for c in icmp)
    assert all(" application " in c.command for c in icmp if c.expected.startswith("allow"))


# -- the source side: packet-tracer needs ASA 7.2 ----------------------------------------------


@pytest.mark.parametrize(
    ("dialect", "version", "expected"),
    [
        (Dialect.asa, "7.0(1)", False),
        (Dialect.asa, "7.1(2)", False),
        (Dialect.asa, "7.2(1)", True),
        (Dialect.asa, "8.2(5)", True),
        (Dialect.asa, "9.8(4)", True),
        (Dialect.asa, "", False),
        (Dialect.pix, "6.3(5)", False),
        (Dialect.pix, "7.2(1)", False),
        (Dialect.ios, "12.4", False),
    ],
)
def test_packet_tracer_is_only_for_asa_7_2_and_later(
    dialect: Dialect, version: str, expected: bool
) -> None:
    policy = Policy(dialect=dialect, os_version=version)
    assert packet_tracer_supported(policy) is expected


@pytest.mark.parametrize("name", ["pix-2006-hq", "ios-12-edge"])
def test_no_source_commands_are_invented_for_pix_or_ios(name: str) -> None:
    commands = built(name).runbook.commands
    assert commands.source == []
    assert "packet-tracer is not available" in commands.source_note
    assert "7.2" in commands.source_note


@pytest.mark.parametrize("name", ["asa-8.2-branch", "asa-9.8-dc"])
def test_asa_source_commands_have_the_packet_tracer_syntax(name: str) -> None:
    commands = built(name).runbook.commands
    assert commands.source and commands.source_note == ""
    assert {c.id for c in commands.source} <= {c.id for c in commands.target}
    for item in commands.source:
        command = item.command
        shaped = TRACER_TCP_UDP.match(command) or TRACER_ICMP.match(command)
        assert shaped or TRACER_RAW.match(command), command
        assert re.match(r"^(ALLOW|DROP) \(source rule \S+\)$", item.expected), item.expected
        assert command.split()[2] == item.context.split(":")[0]  # the ingress nameif


def test_source_expectations_match_the_hand_verified_golden_flows() -> None:
    b = built("asa-8.2-branch")
    by_id = {v.id: v for v in b.vectors}
    checked = 0
    for item in b.runbook.commands.source:
        if item.origin == "golden":
            vector = by_id[item.id]
            want = "ALLOW" if vector.expect_action.value == "permit" else "DROP"
            assert item.expected.startswith(want) and vector.expect_rule in item.expected
            checked += 1
    assert checked > 0


# -- checklists --------------------------------------------------------------------------------


def test_prechecks_cover_the_governance_p6_list() -> None:
    b = built("asa-8.2-branch")
    steps = b.runbook.prechecks
    text = " ".join(s.text for s in steps)
    for needle in (
        "Back up the running configuration of the source and of the target",
        "validate full",
        "do not commit",
        "static routes",
        "NAT",
        "HA",
        "SIEM",
        "less than 7 days",
        "CAB approval reference",
        "rollback",
    ):
        assert needle in text, needle
    zones = [s for s in steps if s.id.startswith("PRE-ZONE-")]
    assert len(zones) == len([i for i in b.policy.interfaces if i.nameif])
    assert all("ethernet1/" in z.text for z in zones)
    assert len({s.id for s in steps}) == len(steps)


def test_the_cab_reference_in_the_prechecks_follows_the_sidecar() -> None:
    b = built("pix-2006-hq")
    assert "(now: not recorded)" in " ".join(s.text for s in b.runbook.prechecks)
    sidecar = parse_sidecar('{"change": {"cab_reference": "CAB-1234"}}', "json")
    assert "(now: CAB-1234)" in " ".join(s.text for s in b.build(sidecar).prechecks)


def test_cutover_lists_the_command_counts_and_the_mismatch_rule() -> None:
    rb = built("asa-8.2-branch").runbook
    text = " ".join(s.text for s in rb.cutover)
    assert f"Run the {len(rb.commands.target)} target verification commands" in text
    assert f"Run the {len(rb.commands.source)} source packet-tracer commands" in text
    assert f"{len(rb.commands.manual)} manual checks" in text
    assert "A mismatch is a rollback trigger" in text
    pix = " ".join(s.text for s in built("pix-2006-hq").runbook.cutover)
    assert "packet-tracer" not in pix


def test_rollback_has_default_triggers_a_time_limit_and_steps() -> None:
    rb = built("pix-2006-hq").runbook
    assert rb.rollback_triggers == list(DEFAULT_ROLLBACK_TRIGGERS)
    joined = " ".join(rb.rollback_triggers)
    for needle in ("verification command", "P1 or P2 incident", "application owner"):
        assert needle in joined
    assert rb.decision_minutes == DEFAULT_DECISION_MINUTES
    text = " ".join(s.text for s in rb.rollback_steps)
    assert "Re-cable or re-route" in text and "restore its configuration backup" in text


def test_the_sidecar_overrides_the_rollback_and_hypercare_defaults() -> None:
    b = built("pix-2006-hq")
    sidecar = parse_sidecar(
        """
        [runbook]
        rollback_triggers = ["Any severity 1 ticket", "The CAB asks for it"]
        decision_time_limit_minutes = 15
        hypercare_business_days = 20
        """,
        "toml",
    )
    rb = b.build(sidecar)
    assert rb.rollback_triggers == ["Any severity 1 ticket", "The CAB asks for it"]
    assert rb.decision_minutes == 15 and rb.hypercare_days == 20
    assert "for 20 business days" in rb.postchecks[0].text
    assert b.runbook.hypercare_days == DEFAULT_HYPERCARE_DAYS
    assert "for 10 business days" in b.runbook.postchecks[0].text


@pytest.mark.parametrize(
    "overrides",
    [
        {"rollback_triggers": []},
        {"rollback_triggers": ["  "]},
        {"decision_time_limit_minutes": 0},
        {"decision_time_limit_minutes": 1441},
        {"hypercare_business_days": 0},
        {"hypercare_business_days": 91},
        {"unknown_key": 1},
    ],
)
def test_bad_runbook_overrides_are_refused(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        RunbookOverrides.model_validate(overrides)


@pytest.mark.parametrize("name", NAMES)
def test_hypercare_lists_ledger_entries_and_rules_the_proof_did_not_hit(name: str) -> None:
    b = built(name)
    subjects = " ".join(w.subject for w in b.runbook.watch)
    for entry in b.emission.ledger:
        assert f"ledger {entry.id} ({entry.entry_class.value})" in subjects
    for context in b.proof.contexts:
        for rule in (*context.original.unhit, *context.resurrected.unhit):
            assert f"rule {rule}" in subjects


def test_hypercare_says_so_when_there_was_no_proof_and_names_tightened_entries() -> None:
    b = built("pix-2006-hq")
    no_proof = build_runbook(b.policy, b.emission, b.commands, [], None, Sidecar(), secret_total=0)
    assert [w.subject for w in no_proof.watch] == ["all rules"]
    tightened = build_runbook(
        b.policy,
        b.emission,
        b.commands,
        [],
        b.proof,
        Sidecar(),
        secret_total=0,
        tightened_ledger=b.emission.ledger[:1],
    )
    items = [w for w in tightened.watch if w.subject.startswith("tightened ")]
    assert items and all("separate change" in w.reason for w in items)


def test_the_postchecks_cover_signoff_decommission_and_secret_rotation() -> None:
    b = built("pix-2006-hq")
    text = " ".join(s.text for s in b.runbook.postchecks)
    assert "application owner" in text and "Decommission the source" in text
    assert f"Rotate every shared secret that was on the source ({b.secrets} redacted" in text
    assert b.secrets > 0


# -- rendering ---------------------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_runbook_markdown_sections_are_in_order_and_use_plain_words(name: str) -> None:
    text = render_runbook_md(built(name).runbook)
    headings = re.findall(r"^### (.+)$", text, flags=re.MULTILINE)
    assert headings == [
        "Pre-cutover checks (P6)",
        "Cutover steps (P7)",
        "Verification commands on the target (PAN-OS)",
        "Verification commands on the source (ASA packet-tracer)",
        "Checks that need another method",
        "Rollback (P9)",
        "Post-checks and hypercare (P8, P11)",
    ]
    assert not FORBIDDEN.search(text)
    assert "<redacted>" not in text


def test_the_runbook_modules_never_use_the_forbidden_words() -> None:
    necro = Path(runbook_commands.__file__).parent
    modules = (
        "runbook.py",
        "runbook_commands.py",
        "runbook_doc.py",
        "rule_text.py",
        "report_doc.py",
        "secret_counts.py",
    )
    for module in modules:
        assert not FORBIDDEN.search((necro / module).read_text(encoding="utf-8")), module


# -- snapshots ---------------------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_runbook_snapshot_per_sample(name: str) -> None:
    text = render_runbook_md(built(name).runbook)
    path = SNAPSHOTS / f"runbook-{name}.md"
    if os.environ.get("NECRO_UPDATE_SNAPSHOTS") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    assert path.exists(), f"missing snapshot {path.name}; run with NECRO_UPDATE_SNAPSHOTS=1"
    assert path.read_text(encoding="utf-8") == text, (
        f"{path.name} differs from the runbook; review the change, then regenerate it with "
        "NECRO_UPDATE_SNAPSHOTS=1"
    )
