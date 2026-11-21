"""``decide`` for a policy read back from emitted PAN-OS commands (``Dialect.panos``).

PAN-OS evaluates one rulebase top-down. A rule applies when its ``from`` zones include the
ingress zone and its ``to`` zones include the egress zone (empty means any). The egress zone is
the route lookup of the post-NAT destination, which ``evaluate.decide`` has already computed.

Policy-semantics 7: a flow addressed to the device itself is answered by the interface
management profile of the interface that owns the destination address, not by the rulebase.
The reader turns each enabled profile service into one ``MgmtAccess`` entry for that interface.
"""

from __future__ import annotations

from collections.abc import Callable

from necro.ir import Action, Context, Decision, Flow, Policy, Rule
from necro.mgmt import service_of_flow

RuleMatcher = Callable[[Flow, Rule], bool]


def decide_panos(
    policy: Policy, context: Context, flow: Flow, to_zone: str, matches: RuleMatcher
) -> Decision:
    """First matching rule of the rulebase, or the management profile for traffic to the box."""
    if to_zone == "self":
        return _decide_to_the_box(policy, flow)
    for rule in policy.acls.get(context.acl_name, []):
        if rule.inactive:
            continue
        if rule.from_zones and context.interface not in rule.from_zones:
            continue
        if rule.to_zones and to_zone not in rule.to_zones:
            continue
        if matches(flow, rule):
            return Decision(action=rule.action, rule_id=rule.id, to_zone=to_zone)
    return Decision(
        action=Action.deny, rule_id="implicit-deny", to_zone=to_zone, reason="no rule matched"
    )


def _decide_to_the_box(policy: Policy, flow: Flow) -> Decision:
    owner = next(
        (
            i.nameif
            for i in policy.interfaces
            if i.ip_address is not None and i.ip_address.ip == flow.dst
        ),
        "",
    )
    service = service_of_flow(flow)
    if service is not None:
        for access in policy.mgmt_access:
            if (
                access.proto == service
                and access.interface == owner
                and access.src_addr.contains(flow.src)
            ):
                return Decision(
                    action=Action.permit, rule_id=f"mgmt-profile:{service}", to_zone="self"
                )
    return Decision(
        action=Action.deny,
        rule_id="implicit-deny",
        to_zone="self",
        reason="no management service of the interface admits the flow",
    )
