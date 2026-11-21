"""Second-pass resolution for the IOS parser: zones, routes, bindings, ACL classification, mgmt.

IOS has no ``nameif``. Each interface gets a zone name (its description when that is a valid,
unique identifier, otherwise a slug of the hardware name) so the zone/route code, which keys on
``Interface.nameif``, works unchanged (golden flows expect ``LAN`` / ``WAN`` / ``MGMT``).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from necro.ir import Action, Binding, Interface, MgmtAccess, Route, Rule
from necro.parsers.cisco_common import LineLedger, Unsupported
from necro.sets import AddrSet, PortSet

CLASS_POLICY = "policy"
CLASS_MGMT = "management-plane"
CLASS_NON_POLICY = "non-policy"
CLASS_UNUSED = "unused"


@dataclass
class IosIface:
    hw: str
    line: int
    description: str = ""
    ip: ipaddress.IPv4Interface | None = None
    nameif: str = ""


@dataclass
class RawRoute:
    line_no: int
    network: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address | None
    iface: str  # hardware name as written, "" when absent
    distance: int


@dataclass
class IosVty:
    line_no: int
    acl: tuple[int, str] | None = None
    transports: list[str] = field(default_factory=list)


@dataclass
class IosState:
    ledger: LineLedger
    acls: dict[str, list[Rule]] = field(default_factory=dict)
    acl_lines: dict[str, list[int]] = field(default_factory=dict)
    acl_bad: set[str] = field(default_factory=set)
    mgmt_refs: set[str] = field(default_factory=set)
    nonpolicy_refs: set[str] = field(default_factory=set)
    ifaces: list[IosIface] = field(default_factory=list)
    raw_bind: list[tuple[int, str, str, str]] = field(default_factory=list)
    raw_routes: list[RawRoute] = field(default_factory=list)
    vtys: list[IosVty] = field(default_factory=list)
    snmp: list[tuple[int, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Zones
# ---------------------------------------------------------------------------


def _slug(text: str) -> str:
    return "".join(c if (c.isascii() and c.isalnum()) or c in "_.-" else "-" for c in text)[:63]


def assign_zones(ifaces: list[IosIface]) -> list[Interface]:
    """Zone = description when it is a valid unique identifier, else a slug of the hw name."""
    taken: set[str] = set()
    result: list[Interface] = []
    for st in ifaces:
        wanted = st.description
        if not wanted or _slug(wanted) != wanted or not wanted[0].isalnum() or wanted in taken:
            wanted = _slug(st.hw) or "iface"
        name, n = wanted, 1
        while name in taken:
            n += 1
            name = f"{wanted}-{n}"
        taken.add(name)
        st.nameif = name
        result.append(
            Interface(hw_name=st.hw, nameif=name, ip_address=st.ip, description=st.description)
        )
    return result


# ---------------------------------------------------------------------------
# Routes and bindings
# ---------------------------------------------------------------------------


def finish_routes(state: IosState, ifaces: list[IosIface]) -> list[Route]:
    routes: list[Route] = []
    by_hw = {i.hw.lower(): i for i in ifaces}
    for raw in state.raw_routes:
        try:
            iface = _route_interface(raw, by_hw, ifaces)
        except Unsupported as exc:
            state.ledger.unparsed(raw.line_no, exc.reason)
            continue
        routes.append(
            Route(
                network=raw.network,
                next_hop=raw.next_hop,
                interface=iface,
                metric=raw.distance,
            )
        )
        state.ledger.mark(raw.line_no, "migrated", relevant=True)
    return routes


def _route_interface(raw: RawRoute, by_hw: dict[str, IosIface], ifaces: list[IosIface]) -> str:
    if raw.iface:
        if raw.iface.lower().startswith("null"):
            return ""  # discard route: matches no zone
        target = by_hw.get(raw.iface.lower())
        if target is None:
            raise Unsupported("route-unknown-interface")
        return target.nameif
    if raw.next_hop is not None:
        for st in ifaces:
            if st.ip is not None and raw.next_hop in st.ip.network:
                return st.nameif
    raise Unsupported("route-next-hop-unresolved")


def finish_bindings(
    state: IosState, ifaces: list[IosIface]
) -> tuple[list[Binding], dict[str, str]]:
    by_hw = {i.hw: i for i in ifaces}
    bindings: list[Binding] = []
    egress: dict[str, str] = {}
    seen: set[tuple[str, str]] = set()
    for n, hw, acl, direction in state.raw_bind:
        iface = by_hw[hw]
        if acl not in state.acls:
            # IOS permits everything when the ACL doesn't exist; flag it, never guess.
            state.ledger.unparsed(n, "binding-to-undefined-acl")
            continue
        if (hw, direction) in seen:
            state.ledger.unparsed(n, "duplicate-access-group")
            continue
        seen.add((hw, direction))
        bindings.append(
            Binding(
                acl_name=acl,
                interface=iface.nameif,
                direction="in" if direction == "in" else "out",
            )
        )
        if direction == "out":
            egress[iface.nameif] = acl
        state.ledger.mark(n, "migrated", relevant=True)
    return bindings, egress


# ---------------------------------------------------------------------------
# ACL classification by reference (policy-semantics section 3)
# ---------------------------------------------------------------------------


def classify_acls(state: IosState, bound: set[str]) -> dict[str, str]:
    classes: dict[str, str] = {}
    for name in state.acls:
        if name in bound:
            classes[name] = CLASS_POLICY
        elif name in state.mgmt_refs:
            classes[name] = CLASS_MGMT
        elif name in state.nonpolicy_refs:
            classes[name] = CLASS_NON_POLICY
        else:
            classes[name] = CLASS_UNUSED
    for name, cls in classes.items():
        for line_no in state.acl_lines.get(name, []):
            _reclassify_acl_line(state.ledger, line_no, cls)
    return classes


def _reclassify_acl_line(ledger: LineLedger, line_no: int, cls: str) -> None:
    rec = ledger.record(line_no)
    if rec is None or cls == CLASS_POLICY:
        return
    if cls == CLASS_MGMT:
        if rec.classification == "migrated":
            ledger.reclassify(
                line_no, "management-plane", relevant=rec.security_relevant, reason="vty-acl"
            )
        return
    reason = "non-policy-acl" if cls == CLASS_NON_POLICY else "unused-acl"
    if rec.classification == "migrated":
        ledger.reclassify(line_no, "not-policy", relevant=False, reason=reason)
    elif rec.classification == "unparsed":
        ledger.reclassify(line_no, "unparsed", relevant=False, reason=rec.reason)


# ---------------------------------------------------------------------------
# Management plane: vty access-class and SNMP communities
# ---------------------------------------------------------------------------


def _source_set(state: IosState, acl: str) -> AddrSet:
    """Addresses an ACL permits, looking at the source only. Raises when that is not exact."""
    if acl not in state.acls:
        raise Unsupported("access-class-undefined-acl")
    if acl in state.acl_bad:
        raise Unsupported("access-class-acl-incomplete")
    permitted = AddrSet()
    decided = AddrSet()
    for rule in state.acls[acl]:
        m = rule.match
        if (
            m.proto is not None
            or m.dst != AddrSet.any()
            or m.src_ports != PortSet.any()
            or m.dst_ports != PortSet.any()
            or m.icmp_types is not None
            or m.established
        ):
            raise Unsupported("access-class-acl-not-source-only")
        if rule.action == Action.permit:
            permitted = permitted.union(m.src.subtract(decided))
        decided = decided.union(m.src)
    return permitted


def build_mgmt(state: IosState) -> list[MgmtAccess]:
    mgmt: list[MgmtAccess] = []
    for vty in state.vtys:
        src = AddrSet.any()
        if vty.acl is not None:
            line_no, acl = vty.acl
            try:
                src = _source_set(state, acl)
            except Unsupported as exc:
                state.ledger.unparsed(line_no, exc.reason, replace=True)
                continue
        for proto in vty.transports or ["vty"]:
            mgmt.append(MgmtAccess(proto=proto, src_addr=src))
    for line_no, acl in state.snmp:
        try:
            src = _source_set(state, acl) if acl else AddrSet.any()
        except Unsupported as exc:
            state.ledger.unparsed(line_no, exc.reason, replace=True)
            continue
        mgmt.append(MgmtAccess(proto="snmp", src_addr=src, version="v1/v2c"))
    return mgmt
