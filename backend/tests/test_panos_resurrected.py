"""Task 6.5: the PAN-OS reader, and what the emitted text means when ``decide`` evaluates it.

The emitter and the reader are written separately on purpose. ``emit_panos`` writes text;
``read_panos`` parses only that text back into the IR; ``decide`` answers from the result. If the
emitter gets a rule wrong, the answer changes, and these tests see it.
"""

from __future__ import annotations

import ipaddress
from functools import cache

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from necro.contexts import build_contexts, find_context
from necro.emitters import PanosEmission, emit_panos
from necro.emitters.panos_objects import name_list, name_token
from necro.evaluate import decide
from necro.ir import Action, Dialect, Flow, Match, ParseError, Policy
from necro.ledger import covering
from necro.parsers.panos_reader import RULEBASE, _tokenize, read_panos
from necro.sets import AddrSet
from tests.ir_strategies import flows_near, ios_policies, pix_asa_policies
from tests.panos_helpers import policy_of

CONFIGS = ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"]


@cache
def resurrect(config: str) -> tuple[Policy, PanosEmission, Policy]:
    policy = policy_of(config)
    emission = emit_panos(policy)
    return policy, emission, read_panos(emission.text)


def flow(src: str, dst: str, proto: int = 6, dport: int = 0) -> Flow:
    return Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=proto,
        dst_port=dport,
    )


def read(lines: list[str]) -> Policy:
    return read_panos("\n".join(lines) + "\n")


# -- the tokenizer ----------------------------------------------------------------------------


def test_tokenizer_reads_words_quotes_and_lists() -> None:
    line = 'set rulebase security rules r-1 tag [ a "src-acl:x y" ] description "say \\"hi\\""'
    assert _tokenize(line, 1) == [
        "set",
        "rulebase",
        "security",
        "rules",
        "r-1",
        "tag",
        ["a", "src-acl:x y"],
        "description",
        'say "hi"',
    ]


@pytest.mark.parametrize("line", ['set x "open', "set x [ a b", "set x ]"])
def test_tokenizer_rejects_unbalanced_input(line: str) -> None:
    with pytest.raises(ParseError):
        _tokenize(line, 3)


@pytest.mark.pbt
@given(names=st.lists(st.text(min_size=1, max_size=20), min_size=1, max_size=5))
def test_names_the_emitter_quotes_come_back_unchanged(names: list[str]) -> None:
    tokens = _tokenize(f"set tag {name_list(names)}", 1)
    assert tokens[2] == (names[0] if len(names) == 1 else names)
    assert _tokenize(name_token(names[0]), 1) == [names[0]]


# -- reading emitted configs ------------------------------------------------------------------


@pytest.mark.parametrize("config", CONFIGS)
def test_every_emitted_command_is_understood(config: str) -> None:
    _, emission, resurrected = resurrect(config)
    assert resurrected.dialect == Dialect.panos
    rules = resurrected.acls[RULEBASE]
    assert [r.id for r in rules][-1] == "necro-final-deny"
    assert set(emission.rule_sources) == {r.id.split("/")[0] for r in rules}


def test_zones_interfaces_routes_and_profiles_are_read_back() -> None:
    policy, _, resurrected = resurrect("ios-12-edge.cfg")
    assert [(i.nameif, str(i.ip_address)) for i in resurrected.interfaces] == [
        (i.nameif, str(i.ip_address)) for i in policy.interfaces
    ]
    assert [(str(r.network), r.interface) for r in resurrected.routes] == [("0.0.0.0/0", "WAN")]
    wan_services = sorted(m.proto for m in resurrected.mgmt_access if m.interface == "WAN")
    assert wan_services == ["snmp", "ssh", "telnet"]
    assert {c.name for c in build_contexts(resurrected)} == {"WAN:in", "LAN:in", "MGMT:in"}


def test_static_nat_is_read_back_as_a_static_rule() -> None:
    _, _, resurrected = resurrect("asa-8.2-branch.cfg")
    (nat,) = resurrected.nat_rules
    assert (nat.mapped_interface, nat.real_interface) == ("outside", "inside")
    assert nat.mapped_addr == AddrSet.from_host("198.51.100.5")
    assert nat.real_addr == AddrSet.from_host("172.16.30.5")


def test_icmp_type_applications_and_protocol_applications_become_matches() -> None:
    _, _, resurrected = resurrect("ios-12-edge.cfg")
    by_id = {r.id: r.match for r in resurrected.acls[RULEBASE]}
    assert by_id["110-5"].proto == 1 and by_id["110-5"].icmp_types == frozenset({0})
    assert by_id["110-6"].proto == 1 and by_id["110-6"].icmp_types == frozenset({11})


def test_a_rule_with_two_services_reads_as_two_rules_in_order() -> None:
    resurrected = read(
        [
            "set zone a network layer3 ethernet1/1",
            "set service s1 protocol tcp port 80",
            "set service s2 protocol udp port 53",
            "set rulebase security rules r from a",
            "set rulebase security rules r service [ s1 s2 ]",
            "set rulebase security rules r action allow",
        ]
    )
    assert [(r.id, r.match.proto) for r in resurrected.acls[RULEBASE]] == [("r/1", 6), ("r/2", 17)]


def test_all_deny_style_actions_are_denies() -> None:
    for action in ("deny", "drop", "reset-both"):
        resurrected = read([f"set rulebase security rules r action {action}"])
        assert resurrected.acls[RULEBASE][0].action == Action.deny


# -- the reader is strict ---------------------------------------------------------------------

_STATIC_ROUTE = "set network virtual-router default routing-table ip static-route r destination x"


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("show config", "unknown-panos-command"),
        ("set deviceconfig system hostname x", "unknown-panos-command"),
        ("set network interface ethernet ethernet1/1 layer2", "unknown-panos-command"),
        ("set network interface ethernet ethernet1/1 layer3 ip nonsense", "bad-address"),
        (_STATIC_ROUTE, "unknown-panos-command"),
        ("set network profiles interface-management-profile p ntp yes", "bad-profile"),
        ("set address a ip-netmask nonsense", "bad-address"),
        ("set service s protocol sctp port 80", "bad-service"),
        ("set service s protocol tcp port 80-x", "bad-port-list"),
        ("set application a default ident-by-ip-protocol", "bad-application"),
        ("set application a default port tcp/80", "bad-application"),
    ],
)
def test_commands_the_reader_does_not_understand_raise_with_a_code(line: str, code: str) -> None:
    with pytest.raises(ParseError) as caught:
        read_panos(line + "\n")
    assert caught.value.code == code and caught.value.line_no == 1


_ALLOW = "set rulebase security rules r action allow"
_PROTO_APP = "set application x default ident-by-ip-protocol 47"


@pytest.mark.parametrize(
    ("lines", "code"),
    [
        (["set rulebase security rules r source nowhere", _ALLOW], "undefined-address"),
        (["set rulebase security rules r service nowhere", _ALLOW], "undefined-service"),
        (["set rulebase security rules r application nowhere", _ALLOW], "undefined-application"),
        (
            ["set rulebase security rules r source g", "set address-group g static [ g ]", _ALLOW],
            "undefined-address",
        ),
        (["set rulebase security rules r from a"], "bad-rule"),
        (
            [
                "set service s protocol tcp port 80",
                _PROTO_APP,
                "set rulebase security rules r application x",
                "set rulebase security rules r service s",
                _ALLOW,
            ],
            "unsupported-combination",
        ),
        (
            ["set network interface ethernet ethernet1/1 layer3 interface-management-profile p"],
            "undefined-profile",
        ),
        (
            ["set rulebase nat rules n from a", "set rulebase nat rules n source 10.0.0.1/32"],
            "unsupported-nat-rule",
        ),
    ],
)
def test_inconsistent_configs_raise_with_a_code(lines: list[str], code: str) -> None:
    with pytest.raises(ParseError) as caught:
        read(lines)
    assert caught.value.code == code


# -- evaluating the resurrected policy --------------------------------------------------------

BASE_LINES = [
    "set zone inside network layer3 ethernet1/1",
    "set zone outside network layer3 ethernet1/2",
    "set network interface ethernet ethernet1/1 layer3 ip 10.1.0.1/24",
    "set network interface ethernet ethernet1/2 layer3 ip 192.0.2.1/24",
    "set network virtual-router default routing-table ip static-route r destination 0.0.0.0/0 "
    "interface ethernet1/2",
    "set service web protocol tcp port 80",
    "set address srv ip-netmask 10.1.0.5/32",
]


def test_first_matching_rule_wins_and_disabled_rules_do_not_apply() -> None:
    policy = read(
        [
            *BASE_LINES,
            "set rulebase security rules off from outside",
            "set rulebase security rules off action deny",
            "set rulebase security rules off disabled yes",
            "set rulebase security rules allow-web from outside",
            "set rulebase security rules allow-web to inside",
            "set rulebase security rules allow-web destination srv",
            "set rulebase security rules allow-web service web",
            "set rulebase security rules allow-web action allow",
            "set rulebase security rules last action deny",
        ]
    )
    ctx = find_context(policy, "outside:in")
    web = decide(policy, ctx, flow("203.0.113.9", "10.1.0.5", dport=80))
    assert (web.action, web.rule_id, web.to_zone) == (Action.permit, "allow-web", "inside")
    other = decide(policy, ctx, flow("203.0.113.9", "10.1.0.5", dport=81))
    assert (other.action, other.rule_id) == (Action.deny, "last")


def test_rules_apply_only_to_their_from_and_to_zones() -> None:
    policy = read(
        [
            *BASE_LINES,
            "set rulebase security rules r from inside",
            "set rulebase security rules r to outside",
            "set rulebase security rules r action allow",
        ]
    )
    to_outside = flow("10.1.0.9", "203.0.113.9")
    to_inside = flow("10.1.0.9", "10.1.0.77")
    inside, outside = find_context(policy, "inside:in"), find_context(policy, "outside:in")
    assert decide(policy, inside, to_outside).rule_id == "r"
    # the rule does not apply to inside -> inside, so the default intrazone rule decides
    assert decide(policy, inside, to_inside).rule_id == "intrazone-default"
    # nor to outside -> outside: the zone of the ingress interface is wrong for the rule
    assert decide(policy, outside, to_outside).rule_id == "intrazone-default"
    # and outside -> inside is between zones, where PAN-OS denies by default
    assert decide(policy, outside, to_inside).rule_id == "interzone-default"


def test_a_rulebase_with_no_match_falls_back_to_the_pan_os_default_rules() -> None:
    """PAN-OS allows traffic within a zone and denies traffic between zones when no rule matches.

    This is why the emitter ends every rulebase with an explicit final deny.
    """
    policy = read(BASE_LINES)
    inside = find_context(policy, "inside:in")
    between = decide(policy, inside, flow("10.1.0.9", "203.0.113.9"))
    assert (between.action, between.rule_id) == (Action.deny, "interzone-default")
    within = decide(policy, inside, flow("10.1.0.9", "10.1.0.77"))
    assert (within.action, within.rule_id, within.to_zone) == (
        Action.permit,
        "intrazone-default",
        "inside",
    )


def test_the_explicit_final_deny_overrides_the_intrazone_default() -> None:
    policy = read([*BASE_LINES, "set rulebase security rules last action deny"])
    got = decide(policy, find_context(policy, "inside:in"), flow("10.1.0.9", "10.1.0.77"))
    assert (got.action, got.rule_id) == (Action.deny, "last")


def test_predefined_icmp_app_ids_are_read_as_the_broad_matches_they_are() -> None:
    lines = [*BASE_LINES, "set rulebase security rules r action allow"]
    unreachable = (
        "set application necro-icmp-3 category networking subcategory ip-protocol "
        "technology network-protocol risk 1 default ident-by-icmp-type type 3"
    )

    def match(apps: str) -> Match:
        rule = f"set rulebase security rules r application {apps}"
        return read([*lines, unreachable, rule]).acls[RULEBASE][0].match

    ping, icmp, both = match("ping"), match("icmp"), match("[ ping necro-icmp-3 ]")
    assert (ping.proto, ping.icmp_types) == (1, frozenset({0, 8}))
    assert (icmp.proto, icmp.icmp_types) == (1, None)  # every ICMP type
    assert (both.proto, both.icmp_types) == (1, frozenset({0, 3, 8}))


def test_traffic_to_the_box_is_answered_by_the_interface_profile_not_the_rulebase() -> None:
    policy = read(
        [
            *BASE_LINES,
            "set network profiles interface-management-profile p ssh yes",
            'set network profiles interface-management-profile p permitted-ip "10.1.0.0/24"',
            "set network interface ethernet ethernet1/1 layer3 interface-management-profile p",
            "set rulebase security rules everything action allow",
        ]
    )
    ctx = find_context(policy, "inside:in")
    admitted = decide(policy, ctx, flow("10.1.0.9", "10.1.0.1", dport=22))
    assert (admitted.action, admitted.rule_id, admitted.to_zone) == (
        Action.permit,
        "mgmt-profile:ssh",
        "self",
    )
    for probe in (
        flow("10.1.0.9", "10.1.0.1", dport=23),  # service not enabled
        flow("203.0.113.9", "10.1.0.1", dport=22),  # source not permitted
        flow("10.1.0.9", "192.0.2.1", dport=22),  # a different interface owns this address
        flow("10.1.0.9", "10.1.0.1", proto=47),  # no service at all
    ):
        assert decide(policy, ctx, probe).action == Action.deny


# -- the resurrected sample configs ----------------------------------------------------------


def _check(
    policy: Policy, emission: PanosEmission, resurrected: Policy, ctx_name: str, f: Flow
) -> None:
    ctx = find_context(policy, ctx_name)
    original = decide(policy, ctx, f)
    zone = emission.zones.of_context(policy, ctx)
    got = decide(resurrected, find_context(resurrected, f"{zone}:in"), f)
    entries = covering(emission.ledger, ctx_name, f)
    declared = {e.new_action for e in entries}
    assert len(declared) <= 1, (ctx_name, f, entries)
    want = declared.pop() if declared else original.action
    assert got.action == want, (ctx_name, f, original, got, [e.id for e in entries])
    assert got.to_zone == emission.zones.of_nameif(original.to_zone), (ctx_name, f, original, got)


@pytest.mark.pbt
@pytest.mark.parametrize("config", CONFIGS)
@settings(deadline=None)
@given(data=st.data())
def test_resurrected_decisions_match_the_source_except_where_the_ledger_says_otherwise(
    config: str, data: st.DataObject
) -> None:
    """Smoke version of P2 (task 8 owns the full oracle): action and to-zone, modulo ledger."""
    policy, emission, resurrected = resurrect(config)
    matches = [r.match for rules in policy.acls.values() for r in rules]
    device = AddrSet()
    for iface in policy.interfaces:
        if iface.ip_address is not None:
            device = device.union(AddrSet.from_host(iface.ip_address.ip))
    matches += [Match(src=device, dst=device)]
    matches += [Match(src=n.real_addr, dst=n.mapped_addr) for n in policy.nat_rules]
    f = data.draw(flows_near(matches))
    ctx = data.draw(st.sampled_from(build_contexts(policy)))
    _check(policy, emission, resurrected, ctx.name, f)


@pytest.mark.pbt
@settings(deadline=None, max_examples=60)
@given(policy=st.one_of(pix_asa_policies(), ios_policies()))
def test_whatever_the_emitter_writes_the_reader_understands(policy: Policy) -> None:
    resurrected = read_panos(emit_panos(policy).text)
    assert {c.name for c in build_contexts(resurrected)} <= {
        f"{z}:in" for z in {i.nameif for i in resurrected.interfaces}
    }
