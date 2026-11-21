"""Autopsy checks beyond shadowed and redundant rules.

Overly broad permits, insecure services, return-traffic rules, rules without a remark, unused
object-groups and ACLs, insecure management and unfiltered interfaces (requirements 3.3 to 3.5,
3.8 to 3.10, 3.13).

Semantics come from ``decide()``: a rule is only reported as exposure when ``decide()`` actually
answers with that rule for a flow inside its effective region, and the implicit behaviour of an
unfiltered interface is read from ``decide()`` results, never restated here. Severity follows the
governance model and depends on the trust of the zone the traffic comes from.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import IntEnum

from necro.boxes import KIND_TCP, KIND_UDP, Box, effective_regions
from necro.contexts import build_contexts
from necro.evaluate import decide
from necro.findings import SEVERITY_RANK, Finding, FindingType, Severity, make_finding
from necro.ir import Action, Context, Dialect, Flow, MgmtAccess, Policy, Rule
from necro.sets import AddrSet, PortSet

UNTRUSTED_NAMES = frozenset(
    {"outside", "internet", "untrust", "untrusted", "wan", "partner", "external", "public"}
)
IMPLICIT_RULE_IDS = frozenset(
    {"implicit-deny", "implicit-security-level", "implicit-permit-no-acl", "same-security-deny"}
)
_PROTO_NAMES = {None: "IP", 1: "ICMP", 6: "TCP", 17: "UDP"}
_SPECIFIC_PORT_LIMIT = 1024  # a rule naming more ports than this is not "a service"
_SNMP_V1V2 = {"", "1", "2", "2c", "v1", "v2c", "v1/v2c"}


class Trust(IntEnum):
    internal = 0
    dmz = 1
    untrusted = 2


def zone_trust(policy: Policy, nameif: str) -> Trust:
    """Trust of a zone: security level 0 or an outside-like name is untrusted (governance 3)."""
    name = nameif.lower()
    iface = next((i for i in policy.interfaces if i.nameif == nameif), None)
    ios = policy.dialect == Dialect.ios
    if name in UNTRUSTED_NAMES or (iface is not None and not ios and iface.security_level == 0):
        return Trust.untrusted
    if "dmz" in name or (iface is not None and not ios and 0 < iface.security_level < 100):
        return Trust.dmz
    return Trust.internal


def acl_contexts(policy: Policy, acl: str) -> list[Context]:
    """Inbound contexts in which ``acl`` is evaluated first (or alone, for a global ACL)."""
    contexts = build_contexts(policy)
    own = [c for c in contexts if c.acl_name == acl]
    return own or [c for c in contexts if c.global_acl_name == acl and not c.acl_name]


def source_zones(policy: Policy, acl: str) -> list[str]:
    """Zones whose traffic ``acl`` filters (empty when it is not bound inbound)."""
    zone_of = {i.hw_name: i.nameif for i in policy.interfaces}
    return [zone_of.get(c.interface, c.interface) for c in acl_contexts(policy, acl)]


def worst_trust(policy: Policy, zones: list[str]) -> Trust:
    return max((zone_trust(policy, z) for z in zones), default=Trust.internal)


def witness_flows(pieces: list[Box], limit: int = 3) -> list[Flow]:
    return [f for piece in pieces[:limit] for f in piece.witnesses()]


def confirm_effective(policy: Policy, acl: str, rule: Rule, pieces: list[Box]) -> tuple[bool, bool]:
    """(report, verified): does decide() answer with ``rule`` for a flow in ``pieces``?

    An ACL that is not bound inbound has no context to ask, so it is reported unverified.
    A bound rule that decide() never selects (blocked by NAT control, egress ACL, ...) is not
    reported as exposure.
    """
    contexts = acl_contexts(policy, acl)
    if not contexts:
        return True, False
    for flow in witness_flows(pieces):
        for ctx in contexts:
            result = decide(policy, ctx, flow)
            if result.rule_id == rule.id and result.action == rule.action:
                return True, True
    return False, True


def _describe(addrs: AddrSet) -> str:
    if addrs == AddrSet.any():
        return "any address"
    nets = addrs.to_networks()
    more = f" and {len(nets) - 1} more" if len(nets) > 1 else ""
    return f"{nets[0]}{more}"


def _port_count(ports: PortSet) -> int:
    return sum(iv.hi - iv.lo + 1 for iv in ports.intervals)


def management_ranges(policy: Policy) -> AddrSet:
    """Networks of interfaces whose zone looks like a management zone."""
    nets = [
        i.ip_address.network
        for i in policy.interfaces
        if i.ip_address is not None and ("mgmt" in i.nameif.lower() or "manag" in i.nameif.lower())
    ]
    return AddrSet.from_cidr_list(nets)


# ---------------------------------------------------------------------------
# Insecure services (requirement 3.4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Service:
    name: str
    kind: str
    ports: PortSet
    scope: str  # "any" zone, only from an "untrusted" zone, or only to a "mgmt" range
    from_untrusted: Severity
    otherwise: Severity


_C, _H, _M = Severity.critical, Severity.high, Severity.medium


def _svc(
    name: str, kind: str, ports: tuple[int, int], scope: str, hot: Severity, cool: Severity
) -> Service:
    return Service(name, kind, PortSet.from_range(*ports), scope, hot, cool)


SERVICES = (
    _svc("telnet (23/tcp)", KIND_TCP, (23, 23), "any", _C, _H),
    _svc("ftp (21/tcp)", KIND_TCP, (21, 21), "any", _H, _M),
    _svc("tftp (69/udp)", KIND_UDP, (69, 69), "any", _C, _H),
    _svc("rsh/rlogin/rexec (512-514/tcp)", KIND_TCP, (512, 514), "any", _C, _H),
    _svc("snmp (161-162/udp)", KIND_UDP, (161, 162), "any", _C, _H),
    _svc("finger (79/tcp)", KIND_TCP, (79, 79), "any", _H, _M),
    _svc("netbios (137-138/udp)", KIND_UDP, (137, 138), "untrusted", _C, _C),
    _svc("netbios-ssn (139/tcp)", KIND_TCP, (139, 139), "untrusted", _C, _C),
    _svc("smb (445/tcp)", KIND_TCP, (445, 445), "untrusted", _C, _C),
    _svc("rdp (3389/tcp)", KIND_TCP, (3389, 3389), "untrusted", _C, _C),
    _svc("rdp to a management range", KIND_TCP, (3389, 3389), "mgmt", _H, _H),
    _svc("http to a management range", KIND_TCP, (80, 80), "mgmt", _H, _H),
    _svc("ldap (389/tcp, clear text)", KIND_TCP, (389, 389), "untrusted", _H, _H),
    _svc("pop3 (110/tcp, clear text)", KIND_TCP, (110, 110), "untrusted", _H, _H),
    _svc("imap (143/tcp, clear text)", KIND_TCP, (143, 143), "untrusted", _H, _H),
)


def _matching_services(
    policy: Policy, rule: Rule, region: list[Box], trust: Trust
) -> list[tuple[Service, list[Box]]]:
    """Insecure services the rule permits, with the part of its region that carries each."""
    ports = rule.match.dst_ports
    if ports == PortSet.any() or _port_count(ports) > _SPECIFIC_PORT_LIMIT:
        return []
    mgmt = management_ranges(policy)
    found: list[tuple[Service, list[Box]]] = []
    for svc in SERVICES:
        if svc.scope == "untrusted" and trust != Trust.untrusted:
            continue
        if svc.scope == "mgmt" and (mgmt.is_empty() or rule.match.dst == AddrSet.any()):
            continue  # a rule that permits every destination is overly-broad, not a mgmt rule
        pieces: list[Box] = []
        for piece in region:
            if piece.kind != svc.kind:
                continue
            narrowed = piece.restrict(3, svc.ports)
            if narrowed is not None and svc.scope == "mgmt":
                narrowed = narrowed.restrict(1, mgmt)
            if narrowed is not None:
                pieces.append(narrowed)
        if pieces:
            found.append((svc, pieces))
    return found


# ---------------------------------------------------------------------------
# Rule-level exposure: overly broad, insecure service, return traffic
# ---------------------------------------------------------------------------


def _is_overly_broad(rule: Rule) -> bool:
    """Any source and any destination with the service unrestricted, or IP with any destination."""
    m = rule.match
    if m.established:
        return False
    if m.proto is None and m.dst == AddrSet.any():
        return True
    narrowed = (
        (m.proto in (6, 17) and m.dst_ports != PortSet.any())
        or m.icmp_types is not None
        or (m.proto in (6, 17) and m.src_ports != PortSet.any())
    )
    return m.src == AddrSet.any() and m.dst == AddrSet.any() and not narrowed


def _broad_scope(rule: Rule) -> str:
    m = rule.match
    proto = _PROTO_NAMES.get(m.proto, f"IP protocol {m.proto}")
    return f"{proto} traffic from {_describe(m.src)} to {_describe(m.dst)}"


def _is_bound(policy: Policy, acl: str) -> bool:
    return any(b.acl_name == acl for b in policy.bindings)


def rule_findings(policy: Policy, acl: str, rules: list[Rule]) -> list[Finding]:
    """Overly-broad, insecure-service and return-traffic findings for permit rules that fire."""
    if not _is_bound(policy, acl):
        return []  # management-plane, non-policy and unused ACLs do not forward traffic
    zones = source_zones(policy, acl)
    trust = worst_trust(policy, zones)
    zone = ", ".join(zones)
    findings: list[Finding] = []
    for rule, region in effective_regions(rules):
        if rule.action != Action.permit or not region:
            continue
        if _is_overly_broad(rule):
            report, verified = confirm_effective(policy, acl, rule, region)
            if report:
                severity = Severity.critical if trust == Trust.untrusted else Severity.high
                findings.append(
                    make_finding(
                        FindingType.overly_broad,
                        severity,
                        rule.id,
                        source_line=rule.source_line,
                        zone=zone,
                        verified=verified,
                        scope=_broad_scope(rule),
                    )
                )
        findings += _service_finding(policy, acl, rule, region, trust, zone)
        findings += _return_traffic_finding(policy, acl, rule, region, zone)
    return findings


def _service_finding(
    policy: Policy, acl: str, rule: Rule, region: list[Box], trust: Trust, zone: str
) -> list[Finding]:
    matches = _matching_services(policy, rule, region, trust)
    if not matches:
        return []
    pieces = [p for _, ps in matches for p in ps]
    report, verified = confirm_effective(policy, acl, rule, pieces)
    if not report:
        return []
    severity = max(
        (s.from_untrusted if trust == Trust.untrusted else s.otherwise for s, _ in matches),
        key=lambda s: SEVERITY_RANK[s],
    )
    return [
        make_finding(
            FindingType.insecure_service,
            severity,
            rule.id,
            source_line=rule.source_line,
            zone=zone,
            verified=verified,
            services=", ".join(s.name for s, _ in matches),
        )
    ]


def _return_traffic_finding(
    policy: Policy, acl: str, rule: Rule, region: list[Box], zone: str
) -> list[Finding]:
    """IOS only: ``established`` and source-port-only permits are session state in disguise."""
    if policy.dialect != Dialect.ios:
        return []
    m = rule.match
    if m.established:
        why = "matches only TCP segments with ACK or RST set (the established keyword)"
    elif m.proto in (6, 17) and m.src_ports != PortSet.any() and m.dst_ports == PortSet.any():
        why = "permits packets by source port only, which is how the reply of a session looks"
    else:
        return []
    report, verified = confirm_effective(policy, acl, rule, region)
    if not report:
        return []
    return [
        make_finding(
            FindingType.return_traffic,
            Severity.medium,
            rule.id,
            source_line=rule.source_line,
            zone=zone,
            verified=verified,
            why=why,
        )
    ]


def remark_findings(policy: Policy) -> list[Finding]:
    """Every rule without a remark has no recorded business justification (requirement 3.13)."""
    zone_by_acl = {acl: ", ".join(source_zones(policy, acl)) for acl in policy.acls}
    return [
        make_finding(
            FindingType.no_remark,
            Severity.low,
            rule.id,
            source_line=rule.source_line,
            zone=zone_by_acl[acl],
        )
        for acl, rules in policy.acls.items()
        for rule in rules
        if not rule.remark
    ]


# ---------------------------------------------------------------------------
# Unused objects and ACLs (requirement 3.5)
# ---------------------------------------------------------------------------


def object_findings(policy: Policy) -> list[Finding]:
    return [
        make_finding(
            FindingType.unused_object,
            Severity.low,
            f"object-group:{og.name}",
            source_line=og.line,
            name=og.name,
        )
        for og in policy.object_groups
        if not og.used
    ]


def _acl_is_unused(policy: Policy, acl: str) -> bool:
    if policy.dialect == Dialect.ios:
        return policy.acl_classes.get(acl) == "unused"
    if any(b.acl_name == acl for b in policy.bindings):
        return False
    # PIX/ASA: VPN, class-map and similar lines aren't parsed, so a name that appears in any
    # line that was not migrated keeps the ACL alive.
    return not any(
        acl in rec.text.split() for rec in policy.line_records if rec.classification != "migrated"
    )


def acl_findings(policy: Policy) -> list[Finding]:
    return [
        make_finding(
            FindingType.unused_acl,
            Severity.low,
            f"acl:{acl}",
            source_line=min((r.source_line for r in rules if r.source_line), default=0),
            name=acl,
        )
        for acl, rules in policy.acls.items()
        if _acl_is_unused(policy, acl)
    ]


# ---------------------------------------------------------------------------
# Insecure management (requirement 3.8)
# ---------------------------------------------------------------------------


def _mgmt_zone(policy: Policy, m: MgmtAccess) -> tuple[Trust, str]:
    if not m.interface:
        vty = m.proto in ("telnet", "ssh", "vty")
        return Trust.internal, "the vty lines" if vty else "the management plane"
    return zone_trust(policy, m.interface), m.interface


def management_findings(policy: Policy) -> list[Finding]:
    """Telnet, plain-HTTP and SNMP v1/v2c management. These come from the management-plane
    model and the line records, which ``decide()`` does not cover, so they are not verified."""
    findings: list[Finding] = []
    snmp_lines: set[int] = set()
    for m in policy.mgmt_access:
        trust, zone = _mgmt_zone(policy, m)
        ref = f"mgmt:{m.proto}@{m.interface or 'vty'}#{m.source_line}"
        if m.proto == "telnet":
            findings.append(_telnet_finding(m, ref, trust, zone))
        elif m.proto == "http" and policy.dialect == Dialect.ios:
            findings.append(_http_finding(m, ref, zone))
        elif m.proto == "snmp" and m.version in _SNMP_V1V2 and m.source_line:
            snmp_lines.add(m.source_line)
            findings.append(_snmp_finding(m.source_line, trust, zone))
    for rec in policy.line_records:
        is_community = rec.text.lower().split()[:2] == ["snmp-server", "community"]
        if is_community and rec.line_no not in snmp_lines:
            snmp_lines.add(rec.line_no)
            findings.append(_snmp_finding(rec.line_no, Trust.internal, "the management plane"))
    return findings


def _telnet_finding(m: MgmtAccess, ref: str, trust: Trust, zone: str) -> Finding:
    return make_finding(
        FindingType.insecure_management,
        Severity.critical if trust == Trust.untrusted else Severity.high,
        ref,
        source_line=m.source_line,
        zone=zone,
        what=f"Telnet management access is allowed on {zone} from {_describe(m.src_addr)}. "
        "Telnet sends the login and every command in clear text.",
        advice="Use SSH instead and remove the telnet access. Until then, limit it to a "
        "dedicated management network.",
    )


def _http_finding(m: MgmtAccess, ref: str, zone: str) -> Finding:
    return make_finding(
        FindingType.insecure_management,
        Severity.high,
        ref,
        source_line=m.source_line,
        zone=zone,
        what="The HTTP server is enabled (ip http server), so the device is managed over HTTP "
        "without TLS.",
        advice="Disable the HTTP server and use the HTTPS server only, with an access class "
        "that limits who can reach it.",
    )


def _snmp_finding(line_no: int, trust: Trust, zone: str) -> Finding:
    return make_finding(
        FindingType.insecure_management,
        Severity.critical if trust == Trust.untrusted else Severity.medium,
        f"mgmt:snmp-v1v2c#{line_no}",
        source_line=line_no,
        zone=zone,
        what="SNMP version 1 or 2c is configured. Its community string is sent in clear text "
        "and acts as a shared password.",
        advice="Move to SNMPv3 with authentication and encryption. Treat the existing community "
        "strings as exposed and rotate them at decommission.",
    )


# ---------------------------------------------------------------------------
# Unfiltered interfaces (requirement 3.9)
# ---------------------------------------------------------------------------


def _probe_flow(src_net: ipaddress.IPv4Network, dst: ipaddress.IPv4Address) -> Flow:
    src = next((h for h in src_net.hosts() if h != dst), ipaddress.IPv4Address("192.0.2.254"))
    return Flow(src=src, dst=dst, proto=6, src_port=40000, dst_port=443)


def interface_findings(policy: Policy) -> list[Finding]:
    """Interfaces with no inbound ACL, naming the implicit behaviour ``decide()`` applies."""
    ios = policy.dialect == Dialect.ios
    by_key = {(i.hw_name if ios else i.nameif): i for i in policy.interfaces}
    findings: list[Finding] = []
    for ctx in build_contexts(policy):
        if ctx.acl_name or ctx.global_acl_name:
            continue
        iface = by_key[ctx.interface]
        src_net = (
            iface.ip_address.network if iface.ip_address else ipaddress.IPv4Network("192.0.2.0/24")
        )
        permitted: list[str] = []
        denied: list[str] = []
        implicit = False
        for other in policy.interfaces:
            if other is iface or other.ip_address is None:
                continue
            host = next(
                (h for h in other.ip_address.network.hosts() if h != other.ip_address.ip), None
            )
            if host is None:
                continue
            result = decide(policy, ctx, _probe_flow(src_net, host))
            implicit = implicit or result.rule_id in IMPLICIT_RULE_IDS
            (permitted if result.action == Action.permit else denied).append(other.nameif)
        findings.append(
            _unfiltered(policy, iface.nameif, iface.source_line, permitted, denied, implicit)
        )
    return findings


def _unfiltered(
    policy: Policy, nameif: str, line: int, permitted: list[str], denied: list[str], implicit: bool
) -> Finding:
    if policy.dialect == Dialect.ios:
        behaviour = (
            "IOS permits all traffic on an interface with no access list (implicit-permit-no-acl)."
        )
    else:
        behaviour = (
            "The implicit security-level rules apply: traffic is permitted towards "
            f"{', '.join(permitted) or 'no interface'} and denied towards "
            f"{', '.join(denied) or 'no interface'}, without any rule recording why."
        )
    trust = zone_trust(policy, nameif)
    return make_finding(
        FindingType.unfiltered_interface,
        Severity.critical if trust == Trust.untrusted else Severity.high,
        f"interface:{nameif}",
        source_line=line,
        zone=nameif,
        verified=implicit,
        name=nameif,
        behaviour=behaviour,
    )
