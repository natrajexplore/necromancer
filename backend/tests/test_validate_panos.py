"""Gate G3: static checks of the emitted PAN-OS candidate (requirement 1.4)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from necro.emitters.panos import emit_panos
from necro.ir import Action, Policy
from necro.ledger import LedgerClass, LedgerEntry
from necro.validate_panos import CHECK_IDS, validate_panos
from tests.ir_strategies import ios_policies, pix_asa_policies
from tests.panos_helpers import policy_of

R = "set rulebase security rules"

BASE = [
    "set network interface ethernet ethernet1/1 layer3 ip 192.0.2.2/30",
    "set network interface ethernet ethernet1/2 layer3 ip 10.20.0.1/16",
    "set zone WAN network layer3 ethernet1/1",
    "set zone LAN network layer3 ethernet1/2",
    "set network virtual-router default interface [ ethernet1/1 ethernet1/2 ]",
    "set network virtual-router default routing-table ip static-route r-0.0.0.0-0 "
    "destination 0.0.0.0/0 interface ethernet1/1 nexthop ip-address 192.0.2.1",
    'set tag "src-acl:110" comments "Source ACL 110"',
    'set tag "necro:final-deny" comments "Explicit final deny"',
    "set address h-10.20.1.10 ip-netmask 10.20.1.10/32",
    "set service tcp-443 protocol tcp port 443",
    "set service-group web members [ tcp-443 ]",
    f"{R} 110-1 from WAN",
    f"{R} 110-1 to LAN",
    f"{R} 110-1 source any",
    f"{R} 110-1 destination h-10.20.1.10",
    f"{R} 110-1 application any",
    f"{R} 110-1 service web",
    f"{R} 110-1 action allow",
    f"{R} 110-1 log-end yes",
    f'{R} 110-1 tag "src-acl:110"',
]
FINAL = [
    f"{R} necro-final-deny from any",
    f"{R} necro-final-deny to any",
    f"{R} necro-final-deny source any",
    f"{R} necro-final-deny destination any",
    f"{R} necro-final-deny application any",
    f"{R} necro-final-deny service any",
    f"{R} necro-final-deny action deny",
    f"{R} necro-final-deny log-start yes",
    f"{R} necro-final-deny log-end yes",
    f'{R} necro-final-deny tag "necro:final-deny"',
]


def rule(name: str, **attrs: str) -> list[str]:
    """An allow rule with every field set; keyword arguments override fields."""
    fields = {"from": "WAN", "to": "LAN", "source": "any", "destination": "any"}
    fields |= {"application": "any", "service": "tcp-443", "action": "allow", "log-end": "yes"}
    fields.update({k.rstrip("_").replace("_", "-"): v for k, v in attrs.items()})
    return [f"{R} {name} {k} {v}" for k, v in fields.items() if v]


def candidate(*extra: str, final: bool = True) -> str:
    return "\n".join([*BASE, *extra, *(FINAL if final else [])])


def entry(entry_id: str) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        entry_class=LedgerClass.tightening,
        reason="approved broad access",
        affected="all traffic",
        context="any",
        old_action=Action.deny,
        new_action=Action.permit,
    )


def error_ids(text: str, ledger: list[LedgerEntry] | None = None) -> set[str]:
    return {c.id for c in validate_panos(text, ledger or []).errors}


def test_a_minimal_valid_candidate_passes_every_check() -> None:
    result = validate_panos(candidate())
    assert result.passed and not result.warnings
    assert [c.id for c in result.checks] == list(CHECK_IDS)
    assert all(c.ok for c in result.checks)


@pytest.mark.parametrize("config", ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"])
def test_the_emitted_samples_have_no_errors(config: str) -> None:
    emission = emit_panos(policy_of(config))
    result = validate_panos(emission.text, emission.ledger)
    assert result.passed, [c.detail for c in result.errors]
    assert {c.id for c in result.warnings} <= {"g3-broad-allow"}


BLOCKING = [
    ("g3-syntax", candidate("show running-config")),
    ("g3-syntax", candidate("set frobnicate everything now")),
    ("g3-syntax", candidate('set tag "unterminated comments x')),
    ("g3-name-valid", candidate("set address -bad ip-netmask 10.0.0.1/32")),
    ("g3-name-valid", candidate("set address " + "a" * 64 + " ip-netmask 10.0.0.1/32")),
    ("g3-name-valid", candidate("set address any ip-netmask 10.0.0.1/32")),
    ("g3-name-valid", candidate("set zone " + "Z" * 32 + " network layer3 ethernet1/1")),
    ("g3-name-valid", candidate("set network interface ethernet eth9 layer3 ip 10.0.0.1/24")),
    ("g3-name-valid", candidate('set tag "' + "t" * 128 + '" comments x')),
    ("g3-name-valid", candidate(*rule("bad*rule"))),
    ("g3-name-unique", candidate(*rule("110-1", to="WAN"))),
    ("g3-name-unique", candidate("set service web protocol tcp port 8443")),
    ("g3-reference", candidate(*rule("r2", destination="h-missing"))),
    ("g3-reference", candidate(*rule("r2", service="svc-missing"))),
    ("g3-reference", candidate(*rule("r2", from_="DMZ"))),
    ("g3-reference", candidate(*rule("r2"), f'{R} r2 tag "no-such-tag"')),
    ("g3-reference", candidate("set zone DMZ network layer3 ethernet1/9")),
    ("g3-reference", candidate("set service-group bundle members [ tcp-443 tcp-8443 ]")),
    ("g3-reference", candidate("set network virtual-router vr2 interface [ ethernet1/7 ]")),
    (
        "g3-reference",
        candidate(
            "set network interface ethernet ethernet1/1 layer3 "
            "interface-management-profile no-such-profile"
        ),
    ),
    ("g3-empty-group", candidate("set service-group empty members [ ]")),
    (
        "g3-empty-group",
        candidate("set service-group a members [ b ]", "set service-group b members [ a ]"),
    ),
    ("g3-rule-fields", candidate(*rule("r2", to=""))),
    ("g3-rule-fields", candidate(*rule("r2", action=""))),
    ("g3-rule-fields", candidate(*rule("r2", action="maybe"))),
    ("g3-final-deny", candidate(final=False)),
    ("g3-final-deny", "\n".join(BASE[:11])),
    ("g3-final-deny", candidate(*rule("last", action="deny", log_end=""), final=False)),
    ("g3-final-deny", candidate(f"{R} necro-final-deny disabled yes")),
    (
        "g3-any-any",
        candidate(*rule("wide", from_="any", to="any", service="any")),
    ),
    ("g3-baseline-service", candidate(*rule("r2", service="application-default"))),
]


@pytest.mark.parametrize(("check_id", "text"), BLOCKING)
def test_every_blocking_condition_is_an_error(check_id: str, text: str) -> None:
    result = validate_panos(text)
    assert check_id in {c.id for c in result.errors}, [c.detail for c in result.checks]
    assert not result.passed
    assert not any(c.ok for c in result.checks if c.id == check_id)


def test_any_to_any_is_allowed_when_its_tag_names_a_ledger_entry() -> None:
    wide = rule("wide", from_="any", to="any", service="any")
    tagged = candidate(
        'set tag "necro:TGT-0001" comments x', *wide, f'{R} wide tag "necro:TGT-0001"'
    )
    assert "g3-any-any" in error_ids(tagged)
    assert "g3-any-any" not in error_ids(tagged, [entry("TGT-0001")])
    assert "g3-any-any" in error_ids(tagged, [entry("TGT-0002")])


def test_a_disabled_any_to_any_rule_is_not_an_error() -> None:
    wide = rule("wide", from_="any", to="any", service="any")
    assert not error_ids(candidate(*wide, f"{R} wide disabled yes"))


def test_warnings_are_listed_and_do_not_block() -> None:
    text = candidate(
        *rule("broad", service="any"),
        *rule("pinger", application="ping"),
        *rule("quiet", log_end=""),
    )
    result = validate_panos(text)
    assert result.passed
    found = {c.id: c.detail for c in result.warnings}
    assert set(found) == {"g3-broad-allow", "g3-predefined-app", "g3-logging"}
    assert "broader than one ICMP type" in found["g3-predefined-app"]
    assert all(c.severity == "warning" for c in result.warnings)


def test_a_final_deny_that_does_not_log_is_a_warning() -> None:
    text = candidate(*[ln for ln in FINAL if " log-" not in ln], final=False)
    result = validate_panos(text)
    assert result.passed
    assert [c.id for c in result.warnings] == ["g3-logging"]


@pytest.mark.parametrize("literal", ["10.1.1.1", "10.1.0.0/16", "10.1.1.1-10.1.1.9"])
def test_literal_addresses_in_rules_resolve(literal: str) -> None:
    assert not error_ids(candidate(*rule("lit", source=literal)))


def test_a_custom_application_is_not_a_predefined_app_id() -> None:
    text = candidate(
        "set application necro-icmp-0 category networking subcategory ip-protocol "
        "technology network-protocol risk 1 default ident-by-icmp-type type 0",
        *rule("echo", application="necro-icmp-0"),
    )
    assert validate_panos(text).warnings == []


def test_failures_come_first_in_check_order_and_every_check_is_reported_once_when_ok() -> None:
    text = candidate(*rule("r2", service="application-default", destination="h-missing"))
    result = validate_panos(text)
    ids = [c.id for c in result.checks]
    failing = [c.id for c in result.checks if not c.ok]
    assert ids[: len(failing)] == failing
    assert failing == sorted(failing, key=CHECK_IDS.index)
    assert sorted(ids[len(failing) :], key=CHECK_IDS.index) == ids[len(failing) :]
    assert set(ids) == set(CHECK_IDS)


def test_every_error_names_where_it_is() -> None:
    result = validate_panos(candidate(*rule("r2", destination="h-missing")))
    (error,) = result.errors
    assert "r2" in error.detail and "h-missing" in error.detail


def test_blank_lines_are_ignored_and_the_result_is_deterministic() -> None:
    text = candidate().replace("\n", "\n\n")
    assert validate_panos(text) == validate_panos(text)
    assert validate_panos(text).passed


@pytest.mark.pbt
@settings(deadline=None)
@given(policy=st.one_of(pix_asa_policies(), ios_policies()))
def test_whatever_the_emitter_writes_passes_g3(policy: Policy) -> None:
    emission = emit_panos(policy)
    result = validate_panos(emission.text, emission.ledger)
    assert result.passed, [c.detail for c in result.errors]
