"""Task 4.5: per-dialect renderers and property P1, parse(render(ir)) == ir (requirement 1.8)."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
from hypothesis import given

from necro.ir import (
    Action,
    Binding,
    Dialect,
    Interface,
    MgmtAccess,
    NatRule,
    NatType,
    Policy,
    Route,
    Rule,
)
from necro.ir import Match as IrMatch
from necro.parsers import parse_config
from necro.parsers.ios_acl import parse_ios
from necro.parsers.pix_asa import parse_pix_asa
from necro.redact import redact
from necro.renderers import UnrenderableError, render, render_ios, render_pix_asa
from necro.sets import AddrSet, PortSet
from tests.ir_strategies import ios_policies, pix_asa_policies

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def core(policy: Policy, *, mgmt: bool = True) -> dict[str, object]:
    """The parts of a Policy that P1 compares: everything except provenance and accounting."""
    return {
        "dialect": policy.dialect,
        "os_version": policy.os_version,
        "mode": policy.mode,
        "address_space": policy.address_space,
        "name_aliases": policy.name_aliases,
        "interfaces": policy.interfaces,
        "routes": policy.routes,
        "bindings": policy.bindings,
        "acls": {
            name: [r.model_copy(update={"source_line": 0}) for r in rules]
            for name, rules in policy.acls.items()
        },
        "egress_acls": policy.egress_acls,
        "nat_rules": policy.nat_rules,
        "nat_control": policy.nat_control,
        "mgmt_access": policy.mgmt_access if mgmt else [],
        "same_security_inter": policy.same_security_inter,
        "same_security_intra": policy.same_security_intra,
    }


def _reparse(ir: Policy, text: str) -> Policy:
    if ir.dialect == Dialect.ios:
        return parse_ios(text)
    return parse_pix_asa(text, dialect=ir.dialect)


# ---------------------------------------------------------------------------
# P1 over generated IR
# ---------------------------------------------------------------------------


@pytest.mark.pbt
@given(pix_asa_policies())
def test_p1_pix_asa_round_trip(ir: Policy) -> None:
    text = render_pix_asa(ir)
    again = parse_pix_asa(text, dialect=ir.dialect)
    assert again.unparsed == [], text
    assert core(again) == core(ir), text


@pytest.mark.pbt
@given(ios_policies())
def test_p1_ios_round_trip(ir: Policy) -> None:
    text = render_ios(ir)
    again = parse_ios(text)
    assert again.unparsed == [] or all(not u.security_relevant for u in again.unparsed), text
    assert core(again) == core(ir), text


@pytest.mark.pbt
@given(pix_asa_policies() | ios_policies())
def test_p1_render_is_a_fixpoint(ir: Policy) -> None:
    """render(parse(render(ir))) == render(ir): the text is canonical."""
    text = render(ir)
    assert render(_reparse(ir, text)) == text


# ---------------------------------------------------------------------------
# P1 on the real samples
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "dialect"),
    [
        ("pix-2006-hq.cfg", Dialect.pix),
        ("asa-8.2-branch.cfg", Dialect.asa),
        ("ios-12-edge.cfg", Dialect.ios),
    ],
)
def test_p1_samples_round_trip(name: str, dialect: Dialect) -> None:
    original = parse_config((SAMPLES / "dead-configs" / name).read_text(encoding="utf-8"))
    text = render(original)
    again = parse_config(text, dialect=dialect)
    ios = dialect == Dialect.ios
    # IOS management access comes from vty/snmp lines, which the renderer doesn't write.
    assert core(again, mgmt=not ios) == core(original, mgmt=not ios)
    assert render(again) == text


def test_rendered_sample_does_not_contain_redacted_secrets() -> None:
    raw = (SAMPLES / "dead-configs" / "asa-8.2-branch.cfg").read_text(encoding="utf-8")
    text = render(parse_config(raw))
    assert "<redacted>" not in text
    assert "enable" not in text and "crypto" not in text
    assert redact(text) == text  # rendering never reintroduces anything redact would touch


# ---------------------------------------------------------------------------
# Renderer behaviour and limits
# ---------------------------------------------------------------------------


def _policy(dialect: Dialect, **kwargs: object) -> Policy:
    return Policy(dialect=dialect, **kwargs)  # type: ignore[arg-type]


def _one_rule(match: IrMatch, **kwargs: object) -> dict[str, list[Rule]]:
    return {"A": [Rule(id="A#1", action=Action.permit, match=match, **kwargs)]}  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "policy",
    [
        _policy(Dialect.asa, acls=_one_rule(IrMatch(proto=6, established=True))),
        _policy(Dialect.asa, acls=_one_rule(IrMatch(proto=6, icmp_types=frozenset({8})))),
        _policy(Dialect.asa, acls=_one_rule(IrMatch(proto=47, dst_ports=PortSet.single(1)))),
        _policy(Dialect.asa, acls=_one_rule(IrMatch(proto=47, src_ports=PortSet.single(1)))),
        _policy(Dialect.asa, acls=_one_rule(IrMatch(proto=6, src_ports=PortSet([])))),
        _policy(Dialect.asa, acls=_one_rule(IrMatch(src=AddrSet()))),
        _policy(Dialect.asa, acls=_one_rule(IrMatch(proto=1, icmp_types=frozenset()))),
        _policy(
            Dialect.asa,
            routes=[Route(network=ipaddress.IPv4Network("10.0.0.0/8"), interface="inside")],
        ),
        _policy(
            Dialect.asa,
            nat_rules=[NatRule(nat_type=NatType.static, real_addr=AddrSet.from_host("10.0.0.1"))],
        ),
        _policy(
            Dialect.asa,
            nat_rules=[
                NatRule(
                    nat_type=NatType.static,
                    proto=6,
                    real_addr=AddrSet.from_host("10.0.0.1"),
                    mapped_addr=AddrSet.from_host("192.0.2.1"),
                )
            ],
        ),
        _policy(
            Dialect.asa,
            nat_rules=[NatRule(nat_type=NatType.dynamic, real_interface="inside")],
        ),
        _policy(
            Dialect.asa,
            nat_rules=[
                NatRule(
                    nat_type=NatType.dynamic,
                    mapped_interface="outside",
                    mapped_addr=AddrSet([(1, 2), (5, 6)]),
                )
            ],
        ),
        _policy(Dialect.asa, mgmt_access=[MgmtAccess(proto="snmp", src_addr=AddrSet.any())]),
        _policy(
            Dialect.asa,
            mgmt_access=[
                MgmtAccess(proto="telnet", src_addr=AddrSet([(1, 2), (5, 6)]), interface="inside")
            ],
        ),
    ],
)
def test_pix_asa_renderer_rejects_what_it_cannot_express(policy: Policy) -> None:
    with pytest.raises(UnrenderableError):
        render(policy)


@pytest.mark.parametrize(
    "acls",
    [
        {"101": _one_rule(IrMatch(src=AddrSet([(1, 2), (5, 6)])))["A"]},
        {"101": _one_rule(IrMatch(proto=6, src_ports=PortSet([(1, 2), (5, 6)])))["A"]},
        {"101": _one_rule(IrMatch(proto=1, icmp_types=frozenset({1, 2})))["A"]},
        {"101": _one_rule(IrMatch(proto=17, established=True))["A"]},
        {"101": _one_rule(IrMatch(proto=47, dst_ports=PortSet.single(1)))["A"]},
        {"101": _one_rule(IrMatch(proto=6, icmp_types=frozenset({1})))["A"]},
        {"101": _one_rule(IrMatch(), inactive=True)["A"]},
        {"101": _one_rule(IrMatch(src=AddrSet()))["A"]},
        {"101": _one_rule(IrMatch(proto=6, dst_ports=PortSet([])))["A"]},
        {"10": _one_rule(IrMatch(proto=6))["A"]},
        {"700": _one_rule(IrMatch())["A"]},
    ],
)
def test_ios_renderer_rejects_what_it_cannot_express(acls: dict[str, list[Rule]]) -> None:
    with pytest.raises(UnrenderableError):
        render(_policy(Dialect.ios, acls=acls))


def test_rendered_text_shape_pix_asa() -> None:
    policy = _policy(
        Dialect.asa,
        os_version="8.2(5)",
        interfaces=[
            Interface(
                hw_name="Ethernet0/0",
                nameif="outside",
                ip_address=ipaddress.IPv4Interface("192.0.2.2/29"),
            )
        ],
        acls=_one_rule(
            IrMatch(
                proto=6,
                src=AddrSet.from_cidr_list(
                    [ipaddress.IPv4Network("10.0.0.0/24"), ipaddress.IPv4Network("10.1.0.1/32")]
                ),
                dst_ports=PortSet.from_neq(22),
            ),
            remark="web",
            log=True,
            log_level="6",
        ),
        bindings=[Binding(acl_name="A", interface="outside", direction="in")],
    )
    text = render(policy)
    assert "ASA Version 8.2(5)" in text
    assert "object-group network NECRO_N0" in text
    assert " network-object host 10.1.0.1" in text
    assert " port-object range 0 21" in text and " port-object range 23 65535" in text
    assert "access-list A remark web" in text
    assert "access-group A in interface outside" in text
    assert text.endswith("\n")


def test_rendered_text_shape_ios() -> None:
    web = _one_rule(IrMatch(proto=6, dst=AddrSet.from_host("10.0.0.1"), established=True))["A"]
    lan = AddrSet.from_network(ipaddress.IPv4Network("10.0.0.0/24"))
    policy = _policy(
        Dialect.ios,
        os_version="12.4",
        interfaces=[
            Interface(
                hw_name="FastEthernet0/0",
                nameif="WAN",
                description="WAN",
                ip_address=ipaddress.IPv4Interface("192.0.2.2/30"),
            )
        ],
        acls={"101": web, "10": _one_rule(IrMatch(src=lan))["A"]},
        routes=[Route(network=ipaddress.IPv4Network("0.0.0.0/0"), interface="WAN", metric=5)],
    )
    text = render(policy)
    assert "access-list 101 permit tcp any host 10.0.0.1 established" in text
    assert "access-list 10 permit 10.0.0.0 0.0.0.255" in text
    assert "ip route 0.0.0.0 0.0.0.0 FastEthernet0/0 5" in text


def test_render_dispatches_on_dialect() -> None:
    assert render(_policy(Dialect.ios, os_version="12.4")).startswith("version 12.4")
    assert render(_policy(Dialect.pix, os_version="6.3(5)")).startswith("PIX Version 6.3(5)")
