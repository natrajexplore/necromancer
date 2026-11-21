"""Second-pass resolution for the PIX/ASA parser.

These steps need the whole file: ACEs need the expanded object-groups, routes and bindings need
the final interface list. Each function marks the source lines it consumed in the ledger.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from necro.ir import Binding, Interface, ParseError, Route, Rule
from necro.parsers.cisco_common import LineLedger, Unsupported, parse_subnet_mask
from necro.parsers.cisco_groups import GroupTable
from necro.parsers.pix_asa_ace import parse_ace


@dataclass
class IfaceState:
    iface: Interface
    line: int
    nameif_line: int = 0
    level_seen: bool = False


@dataclass
class RawAce:
    line_no: int
    acl: str
    tokens: list[str]  # tokens from permit|deny onward; empty for a remark
    remark: str = ""


def interface_address(addr: str, mask: str) -> ipaddress.IPv4Interface:
    try:
        return ipaddress.IPv4Interface(f"{addr}/{parse_subnet_mask(mask)}")
    except ValueError:
        raise Unsupported("bad-ip-address") from None


def build_acls(
    raw_acl: list[RawAce], names: dict[str, str], groups: GroupTable, ledger: LineLedger
) -> dict[str, list[Rule]]:
    """Turn ACE lines into Rules. An unsupported ACE still consumes its ordinal."""
    acls: dict[str, list[Rule]] = {}
    ordinals: dict[str, int] = {}
    pending: dict[str, list[str]] = {}
    for raw in raw_acl:
        if not raw.tokens:
            pending.setdefault(raw.acl, []).append(raw.remark)
            ledger.mark(raw.line_no, "migrated", relevant=False)
            continue
        acls.setdefault(raw.acl, [])
        ordinals[raw.acl] = ordinals.get(raw.acl, 0) + 1
        seq = ordinals[raw.acl]
        remark = " ".join(pending.pop(raw.acl, []))[:1023]
        try:
            ace = parse_ace(raw.tokens, names, groups, raw.line_no)
        except Unsupported as exc:
            ledger.unparsed(raw.line_no, exc.reason)
            continue
        except ParseError as err:
            raise ParseError(err.code, err.message, raw.line_no) from None
        for match in ace.matches:
            acls[raw.acl].append(
                Rule(
                    id=f"{raw.acl}#{seq}",
                    action=ace.action,
                    match=match,
                    inactive=ace.attrs.inactive,
                    remark=remark,
                    time_range=ace.attrs.time_range,
                    log=ace.attrs.log,
                    log_level=ace.attrs.log_level,
                    source_line=raw.line_no,
                )
            )
        ledger.mark(raw.line_no, "migrated", relevant=True)
    return acls


def finish_interfaces(
    ifaces: list[IfaceState], pending_ip: list[tuple[int, str, str, str]], ledger: LineLedger
) -> list[Interface]:
    """Attach PIX-style ``ip address`` lines; drop interfaces without a nameif."""
    for n, nameif, addr, mask in pending_ip:
        target = next((s for s in ifaces if s.iface.nameif == nameif), None)
        try:
            if target is None:
                raise Unsupported("ip-address-unknown-interface")
            target.iface.ip_address = interface_address(addr, mask)
        except Unsupported as exc:
            ledger.unparsed(n, exc.reason)
        else:
            ledger.mark(n, "migrated", relevant=True)
    result: list[Interface] = []
    for st in ifaces:
        if not st.iface.nameif:
            continue
        if not st.level_seen:
            ledger.reclassify(
                st.nameif_line, "unparsed", relevant=True, reason="missing-security-level"
            )
        result.append(st.iface)
    return result


def finish_routes(
    raw_routes: list[tuple[int, Route]], interfaces: list[Interface], ledger: LineLedger
) -> list[Route]:
    known = {i.nameif for i in interfaces}
    routes: list[Route] = []
    for n, route in raw_routes:
        if route.interface not in known:
            ledger.unparsed(n, "route-unknown-interface")
        else:
            routes.append(route)
            ledger.mark(n, "migrated", relevant=True)
    return routes


def finish_bindings(
    raw_bind: list[tuple[int, list[str]]],
    acls: dict[str, list[Rule]],
    interfaces: list[Interface],
    ledger: LineLedger,
) -> tuple[list[Binding], dict[str, str]]:
    known = {i.nameif for i in interfaces}
    bindings: list[Binding] = []
    egress: dict[str, str] = {}
    seen: set[tuple[str, str]] = set()
    for n, tokens in raw_bind:
        try:
            binding = _parse_binding(tokens, acls, known)
        except Unsupported as exc:
            ledger.unparsed(n, exc.reason)
            continue
        if binding is None:  # control-plane ACL: management plane
            ledger.mark(n, "management-plane", relevant=True)
            continue
        key = ("", "global") if binding.global_acl else (binding.interface, binding.direction)
        if key in seen:
            ledger.unparsed(n, "duplicate-access-group")
            continue
        seen.add(key)
        bindings.append(binding)
        if binding.direction == "out":
            egress[binding.interface] = binding.acl_name
        ledger.mark(n, "migrated", relevant=True)
    return bindings, egress


def _parse_binding(
    tokens: list[str], acls: dict[str, list[Rule]], known_interfaces: set[str]
) -> Binding | None:
    if len(tokens) < 3:
        raise Unsupported("bad-access-group")
    acl, mode = tokens[1], tokens[2].lower()
    if acl not in acls:
        raise Unsupported("access-group-undefined-acl")
    if mode == "global" and len(tokens) == 3:
        return Binding(acl_name=acl, interface="", direction="in", global_acl=True)
    if mode in ("in", "out") and len(tokens) >= 5 and tokens[3].lower() == "interface":
        iface = tokens[4]
        if iface not in known_interfaces:
            raise Unsupported("access-group-unknown-interface")
        extra = [t.lower() for t in tokens[5:]]
        if extra == ["control-plane"]:
            return None
        if extra:
            raise Unsupported("access-group-option-unsupported")
        return Binding(acl_name=acl, interface=iface, direction="in" if mode == "in" else "out")
    raise Unsupported("bad-access-group")
