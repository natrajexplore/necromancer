"""decide(policy, context, flow) -> Decision.

Single source of truth for all policy semantics. Autopsy, gates and the oracle
all call this function. Parsers and emitters never call it directly.

Semantics implemented (see policy-semantics steering for the authoritative spec):
  PIX/ASA:
    - First-match ACL with implicit deny
    - inactive ACEs excluded from evaluation
    - Security-level implicit permit/deny when no ACL is bound
    - same-security-traffic inter/intra-interface logic
    - nat-control: flows without a translation are denied (no-translation)
    - Outbound ACL: ingress AND egress must permit
    - ACLs do NOT filter to-the-box traffic (management-plane on PIX/ASA)

  ASA 8.3+ (global ACL):
    - Interface ACL (if any) -> global ACL (if any) -> implicit deny
    - Once a global ACL exists, security-level permits are gone for ALL interfaces

  IOS:
    - No ACL on an interface -> implicit-permit-no-acl
    - Stateless; no security levels

PBT P8: the evaluator never raises on any well-formed flow (total function).
"""

from __future__ import annotations

from necro.ir import (
    Action,
    AddressSpace,
    Context,
    Decision,
    Dialect,
    Flow,
    Match,
    Policy,
    Rule,
)
from necro.nat import NatModel
from necro.zones import RouteTable, build_route_table

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _flow_matches_rule(flow: Flow, rule: Rule) -> bool:
    """Return True if the flow matches the rule's match criteria."""
    m: Match = rule.match

    # Protocol check
    if m.proto is not None and m.proto != flow.proto:
        return False

    # Address checks
    if not m.src.contains(flow.src):
        return False
    if not m.dst.contains(flow.dst):
        return False

    # Port checks (TCP=6, UDP=17)
    if flow.proto in (6, 17):
        if not m.src_ports.contains(flow.src_port):
            return False
        if not m.dst_ports.contains(flow.dst_port):
            return False
        # IOS established flag: rule requires established, flow must have it
        if m.established and not flow.established:
            return False

    # ICMP type check (proto=1)
    return not (
        flow.proto == 1
        and m.icmp_types is not None
        and (flow.icmp_type is None or flow.icmp_type not in m.icmp_types)
    )


def _eval_acl(acl_rules: list[Rule], flow: Flow) -> Decision | None:
    """Evaluate flow against an ordered ACL.

    Returns a Decision on first match, None on fall-through.
    Inactive rules are skipped. The implicit deny is not added here.
    """
    for rule in acl_rules:
        if rule.inactive:
            continue
        if _flow_matches_rule(flow, rule):
            return Decision(action=rule.action, rule_id=rule.id)
    return None


def _security_level_decision(
    src_level: int,
    dst_level: int,
    same_security_inter: bool,
    flow_is_intrazone: bool,
    same_security_intra: bool,
) -> Decision:
    """Decide a flow based on security levels when no ACL is bound."""
    if flow_is_intrazone:
        if same_security_intra:
            return Decision(
                action=Action.permit,
                rule_id="implicit-security-level",
                reason="intra-interface permitted",
            )
        return Decision(
            action=Action.deny,
            rule_id="same-security-deny",
            reason="hairpin not permitted (same-security-traffic intra-interface not set)",
        )

    if src_level > dst_level:
        return Decision(
            action=Action.permit,
            rule_id="implicit-security-level",
            reason=f"src level {src_level} > dst level {dst_level}",
        )
    if src_level == dst_level:
        if same_security_inter:
            return Decision(
                action=Action.permit,
                rule_id="implicit-security-level",
                reason="same-security-traffic inter-interface permitted",
            )
        return Decision(
            action=Action.deny,
            rule_id="same-security-deny",
            reason=f"equal security levels ({src_level}) without same-security-traffic permit",
        )
    # src_level < dst_level
    return Decision(
        action=Action.deny,
        rule_id="implicit-deny",
        reason=f"src level {src_level} < dst level {dst_level}",
    )


def _lookup_interface_level(policy: Policy, nameif: str) -> int:
    """Return the security level for nameif, or 0 if not found."""
    for iface in policy.interfaces:
        if iface.nameif == nameif:
            return iface.security_level
    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def decide(policy: Policy, context: Context, flow: Flow) -> Decision:
    """Evaluate flow in context and return a Decision.

    Total over well-formed flows (P8) by construction, not by catching errors:
    an unexpected exception is a bug and must surface.
    """
    route_table = build_route_table(policy)
    to_zone = _egress_zone(policy, context, flow, route_table)
    decision = _decide_inner(policy, context, flow, to_zone, route_table)
    # Every decision reports the egress zone from the route lookup, denies included
    # (policy-semantics section 7 compares to_zone for every flow; golden-flows README).
    if decision.to_zone != to_zone:
        decision = decision.model_copy(update={"to_zone": to_zone})
    return decision


def _egress_zone(policy: Policy, context: Context, flow: Flow, route_table: RouteTable) -> str:
    """Zone of the longest-prefix match on the *real* destination (policy-semantics 1.5, 5).

    Pre-8.3 ACLs are written in mapped addresses, so a flow arriving on a static's mapped
    interface is looked up by the real address it translates to. For ASA 8.3+ and IOS the flow
    already carries the real address.
    """
    dst = flow.dst
    if policy.dialect in (Dialect.pix, Dialect.asa) and policy.address_space == AddressSpace.mapped:
        dst = NatModel(policy).map_destination(context.interface, flow.dst, flow)
    return route_table.to_zone(dst)


def _decide_inner(
    policy: Policy, context: Context, flow: Flow, to_zone: str, route_table: RouteTable
) -> Decision:
    # On PIX/ASA, to-the-box traffic bypasses security ACLs (management-plane).
    # On IOS, inbound ACLs do filter to-self traffic, so we continue.
    if policy.dialect in (Dialect.pix, Dialect.asa) and to_zone == "self":
        return Decision(
            action=Action.permit,
            rule_id="implicit-security-level",
            to_zone="self",
            reason="to-the-box traffic bypasses security ACLs on PIX/ASA",
        )

    if policy.dialect == Dialect.ios:
        return _decide_ios(policy, context, flow, to_zone)

    return _decide_pix_asa(policy, context, flow, to_zone, route_table)


def _decide_ios(policy: Policy, context: Context, flow: Flow, to_zone: str) -> Decision:
    """IOS stateless evaluation (no security levels)."""
    acl_name = context.acl_name

    if not acl_name:
        permit = Decision(action=Action.permit, rule_id="implicit-permit-no-acl", to_zone=to_zone)
        return _apply_egress_acl(policy, context, flow, to_zone, permit)

    rules = policy.acls.get(acl_name, [])
    result = _eval_acl(rules, flow)
    if result is not None:
        result.to_zone = to_zone
        if result.action == Action.permit:
            return _apply_egress_acl(policy, context, flow, to_zone, result)
        return result

    return Decision(action=Action.deny, rule_id="implicit-deny", to_zone=to_zone)


def _decide_pix_asa(
    policy: Policy,
    context: Context,
    flow: Flow,
    to_zone: str,
    route_table: RouteTable,
) -> Decision:
    """PIX/ASA stateful evaluation with security levels and NAT-control."""
    has_global_acl = bool(context.global_acl_name)
    acl_name = context.acl_name

    # NAT-control check: PIX always enforces, ASA only when nat_control is set.
    nat_control_active = policy.dialect == Dialect.pix or policy.nat_control
    if nat_control_active:
        nat_model = NatModel(policy)
        if not nat_model.translates(context.interface, flow):
            return Decision(
                action=Action.deny,
                rule_id="implicit-deny",
                to_zone="",
                reason="no-translation: nat-control requires a matching translation",
            )

    if acl_name:
        # ACL is bound: ACL alone decides (security levels no longer grant).
        rules = policy.acls.get(acl_name, [])
        result = _eval_acl(rules, flow)
        if result is not None:
            if result.action == Action.deny:
                # Explicit deny in the interface ACL is final.
                return Decision(action=Action.deny, rule_id=result.rule_id, to_zone="")
            permit_decision = Decision(
                action=Action.permit, rule_id=result.rule_id, to_zone=to_zone
            )
            return _apply_egress_acl(policy, context, flow, to_zone, permit_decision)

        # No match in interface ACL: fall through to global ACL, or implicit deny.
        if has_global_acl:
            return _eval_global_acl(policy, context, flow, to_zone)
        return Decision(action=Action.deny, rule_id="implicit-deny", to_zone="")

    else:
        # No ACL bound.
        if has_global_acl:
            # Global ACL eliminates security-level implicit permits.
            return _eval_global_acl(policy, context, flow, to_zone)

        # Pure security-level decision.
        src_level = _lookup_interface_level(policy, context.interface)
        dst_level = _lookup_interface_level(policy, to_zone) if to_zone else 0
        flow_is_intrazone = context.interface == to_zone

        level_decision = _security_level_decision(
            src_level,
            dst_level,
            policy.same_security_inter,
            flow_is_intrazone,
            policy.same_security_intra,
        )
        if level_decision.action == Action.deny:
            return level_decision
        permit_decision = Decision(
            action=Action.permit,
            rule_id=level_decision.rule_id,
            to_zone=to_zone,
            reason=level_decision.reason,
        )
        return _apply_egress_acl(policy, context, flow, to_zone, permit_decision)


def _eval_global_acl(policy: Policy, context: Context, flow: Flow, to_zone: str) -> Decision:
    """Evaluate a flow against the global ACL (ASA 8.3+)."""
    global_rules = policy.acls.get(context.global_acl_name, [])
    g_result = _eval_acl(global_rules, flow)
    if g_result is not None:
        if g_result.action == Action.deny:
            return Decision(action=Action.deny, rule_id=g_result.rule_id, to_zone="")
        permit_decision = Decision(action=Action.permit, rule_id=g_result.rule_id, to_zone=to_zone)
        return _apply_egress_acl(policy, context, flow, to_zone, permit_decision)
    return Decision(action=Action.deny, rule_id="implicit-deny", to_zone="")


def _apply_egress_acl(
    policy: Policy,
    context: Context,
    flow: Flow,
    to_zone: str,
    ingress_decision: Decision,
) -> Decision:
    """Check the egress interface's outbound ACL after ingress permits (policy-semantics 1.4).

    The ACL is looked up by the flow's egress interface (``to_zone``), never by the
    ingress context. An egress interface with no outbound ACL leaves the ingress
    decision unchanged. A bound outbound ACL has an implicit deny.
    """
    egress_acl = policy.egress_acls.get(to_zone)
    if not egress_acl:
        return ingress_decision

    rules = policy.acls.get(egress_acl, [])
    result = _eval_acl(rules, flow)
    if result is None:
        return Decision(
            action=Action.deny,
            rule_id="implicit-deny",
            to_zone="",
            reason="egress ACL implicit deny",
        )
    if result.action == Action.permit:
        return ingress_decision
    return Decision(
        action=Action.deny,
        rule_id=result.rule_id,
        to_zone="",
        reason="denied by egress ACL",
    )
