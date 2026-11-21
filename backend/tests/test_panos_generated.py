"""Task 6.5: resurrected decisions match the source on generated policies, modulo the ledger.

This is the emitter's own cross-check against ``read_panos`` and ``decide`` on policies nobody
wrote by hand: nat-control, static NAT, outbound ACLs, global ACLs, ICMP types, other IP
protocols, inactive rules, implicit permits. Task 8 owns the full oracle (P2); this keeps the
emitter honest while it is being built.
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from necro.boxes import boxes_of
from necro.contexts import build_contexts, find_context
from necro.emitters import emit_panos
from necro.evaluate import decide
from necro.ir import Context, Flow, Match, NatRule, NatType, Policy
from necro.ledger import covering
from necro.parsers.panos_reader import read_panos
from necro.sets import AddrSet
from tests.ir_strategies import flows_near, ios_policies, pix_asa_policies


def _boundary_matches(policy: Policy) -> list[Match]:
    matches = [r.match for rules in policy.acls.values() for r in rules]
    device = AddrSet()
    for iface in policy.interfaces:
        if iface.ip_address is not None:
            device = device.union(AddrSet.from_host(iface.ip_address.ip))
    matches.append(Match(src=device, dst=device))
    matches += [Match(src=n.real_addr, dst=n.mapped_addr) for n in policy.nat_rules]
    matches += [Match(src=m.src_addr, dst=device) for m in policy.mgmt_access]
    networks = [i.ip_address.network for i in policy.interfaces if i.ip_address is not None]
    networks += [r.network for r in policy.routes]
    matches += [Match(src=AddrSet.from_network(n), dst=AddrSet.from_network(n)) for n in networks]
    return matches


def _tuned(policy: Policy, *, no_egress: bool, translate_everything: bool) -> Policy:
    """Generated policies are dominated by outbound ACLs and nat-control denies; this lets the
    ACL logic through. ``translate_everything`` adds the ``nat (iface) 1 0 0`` real configs have."""
    update: dict[str, object] = {}
    if no_egress:
        update["egress_acls"] = {}
    if translate_everything:
        catch_all = [
            NatRule(nat_type=NatType.dynamic, real_interface=i.nameif, real_addr=AddrSet.any())
            for i in policy.interfaces
        ]
        update["nat_rules"] = [*policy.nat_rules, *catch_all]
    return policy.model_copy(update=update)


def _witnesses(policy: Policy, ctx: Context) -> list[Flow]:
    """Flows inside the boxes of the rules ``ctx`` evaluates (lowest and highest values)."""
    acls = [name for name in (ctx.acl_name, ctx.global_acl_name) if name]
    return [
        flow
        for name in acls
        for rule in policy.acls.get(name, [])
        for box in boxes_of(rule.match)
        for flow in box.witnesses()
    ]


@pytest.mark.pbt
@settings(deadline=None)
@given(data=st.data())
def test_generated_policies_resurrect_to_the_same_decisions_modulo_the_ledger(
    data: st.DataObject,
) -> None:
    policy = _tuned(
        data.draw(st.one_of(pix_asa_policies(), ios_policies())),
        no_egress=data.draw(st.booleans()),
        translate_everything=data.draw(st.booleans()),
    )
    emission = emit_panos(policy)
    assume(not emission.unsupported)  # unsupported constructs block the verdict instead
    resurrected = read_panos(emission.text)
    contexts = build_contexts(policy)
    assume(contexts)
    with_acl = [c for c in contexts if c.acl_name or c.global_acl_name]
    ctx = data.draw(
        st.sampled_from(with_acl if with_acl and data.draw(st.booleans()) else contexts)
    )
    witnesses = _witnesses(policy, ctx)
    flows = flows_near(_boundary_matches(policy))
    f = data.draw(st.sampled_from(witnesses) if witnesses and data.draw(st.booleans()) else flows)
    original = decide(policy, find_context(policy, ctx.name), f)
    zone = emission.zones.of_context(policy, ctx)
    got = decide(resurrected, find_context(resurrected, f"{zone}:in"), f)
    entries = covering(emission.ledger, ctx.name, f)
    declared = {e.new_action for e in entries}
    assert len(declared) <= 1, (ctx.name, f, [e.id for e in entries])
    want = declared.pop() if declared else original.action
    assert got.action == want, (ctx.name, f, original, got, [e.id for e in entries])
    assert got.to_zone == emission.zones.of_nameif(original.to_zone), (ctx.name, f, original, got)
