"""Cisco IOS 12.x parser: redacted config text -> Policy IR (requirements 1.2, 1.11, 1.12).

Standard and extended ACLs (numbered, named, sequence numbers, remarks, ``established``), interface
bindings in/out, ``ip route``, vty ``access-class`` and SNMP community ACL references. Every ACL is
classified by what references it (policy / management-plane / non-policy / unused) once the whole
file has been read. Every line is classified exactly once through ``LineLedger``.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

from necro.ir import AddressSpace, Dialect, Policy, PolicyMode, Rule
from necro.parsers import ios_finish as fin
from necro.parsers import ios_tables as tables
from necro.parsers.cisco_common import (
    Classification,
    LineLedger,
    Unsupported,
    is_comment_or_blank,
    is_indented,
    looks_like_ipv4,
    parse_subnet_mask,
    split_lines,
)
from necro.parsers.ios_ace import parse_ios_ace

_Handler = Callable[[int, list[str]], None]


@dataclass
class _Block:
    kind: str  # "interface" | "acl" | "vty" | "inherit"
    iface: fin.IosIface | None = None
    acl: str = ""
    standard: bool = False
    vty: fin.IosVty | None = None
    classification: Classification = "not-policy"
    relevant: bool = False
    reason: str = ""


def _acl_is_standard(number: int) -> bool | None:
    if 1 <= number <= 99 or 1300 <= number <= 1999:
        return True
    if 100 <= number <= 199 or 2000 <= number <= 2699:
        return False
    return None


class _IosParser:
    def __init__(self, text: str, os_version: str) -> None:
        self.text = text
        self.lines = split_lines(text)
        self.ledger = LineLedger(self.lines)
        self.state = fin.IosState(self.ledger)
        self.os_version = os_version
        self.block: _Block | None = None
        self.banner_delim = ""
        self.ordinals: dict[str, int] = {}
        self.last_seq: dict[str, int] = {}
        self.pending_remark: dict[str, list[str]] = {}
        self.handlers: dict[str, _Handler] = {
            "version": self._cmd_version,
            "interface": self._cmd_interface,
            "access-list": self._cmd_access_list,
            "ip": self._cmd_ip,
            "line": self._cmd_line,
            "snmp-server": self._cmd_snmp,
            "ntp": self._cmd_ntp,
            "banner": self._cmd_banner,
            "router": self._cmd_router,
            "route-map": self._cmd_route_map,
            "crypto": self._cmd_crypto,
            "class-map": self._cmd_qos,
            "policy-map": self._cmd_qos,
            "object-group": self._cmd_object_group,
            "control-plane": self._cmd_control_plane,
            "no": self._cmd_no,
            "distribute-list": self._cmd_distribute_list,
        }

    # ------------------------------------------------------------------
    # Driver
    # ------------------------------------------------------------------

    def parse(self) -> Policy:
        for n, line in enumerate(self.lines, 1):
            self._walk_line(n, line)
        st = self.state
        interfaces = fin.assign_zones(st.ifaces)
        routes = fin.finish_routes(st, st.ifaces)
        bindings, egress = fin.finish_bindings(st, st.ifaces)
        classes = fin.classify_acls(st, {b.acl_name for b in bindings})
        mgmt = fin.build_mgmt(st)
        records, unparsed = self.ledger.finalize()
        return Policy(
            dialect=Dialect.ios,
            os_version=self.os_version,
            mode=PolicyMode.routed,
            address_space=AddressSpace.as_is,
            interfaces=interfaces,
            routes=routes,
            bindings=bindings,
            acls=st.acls,
            egress_acls=egress,
            mgmt_access=mgmt,
            line_records=records,
            unparsed=unparsed,
            acl_classes=classes,
            input_sha256=hashlib.sha256(self.text.encode("utf-8")).hexdigest(),
        )

    def _walk_line(self, n: int, line: str) -> None:
        if self.banner_delim:
            self.ledger.mark(n, "not-policy", reason="banner")
            if self.banner_delim in line:
                self.banner_delim = ""
            return
        if is_comment_or_blank(line):
            self.ledger.mark(n, "not-policy")
            return
        tokens = line.split()
        if is_indented(line):
            self._child_line(n, tokens)
            return
        self.block = None
        kw = tokens[0].lower()
        try:
            handler = self.handlers.get(kw)
            if handler is not None:
                handler(n, tokens)
            else:
                self._generic(n, kw)
        except Unsupported as exc:
            self.ledger.unparsed(n, exc.reason)
            self.block = _Block(
                "inherit", classification="unparsed", relevant=True, reason=exc.reason
            )

    def _generic(self, n: int, kw: str) -> None:
        if kw in tables.NOT_POLICY:
            self.ledger.mark(n, "not-policy")
            self.block = _Block("inherit")
        elif kw in tables.RELEVANT_UNSUPPORTED:
            raise Unsupported(tables.RELEVANT_UNSUPPORTED[kw])
        else:
            raise Unsupported("unrecognized-command")

    def _inherit(self, n: int, classification: Classification, reason: str) -> None:
        """Classify an irrelevant, un-migrated block header; its children share the class."""
        if classification in ("out-of-scope", "unparsed"):
            self.ledger.unparsed(
                n,
                reason,
                relevant=False,
                classification="out-of-scope" if classification == "out-of-scope" else "unparsed",
            )
        else:
            self.ledger.mark(n, classification, reason=reason)
        self.block = _Block("inherit", classification=classification, reason=reason)

    # ------------------------------------------------------------------
    # Indented lines
    # ------------------------------------------------------------------

    def _child_line(self, n: int, tokens: list[str]) -> None:
        block = self.block
        if block is None:
            self.ledger.unparsed(n, "orphan-indented-line")
            return
        try:
            if block.kind == "interface" and block.iface is not None:
                self._interface_child(n, tokens, block.iface)
            elif block.kind == "acl":
                self._acl_child(n, tokens, block)
            elif block.kind == "vty" and block.vty is not None:
                self._vty_child(n, tokens, block.vty)
            else:
                self._inherited_child(n, tokens, block)
        except Unsupported as exc:
            if block.kind == "acl":
                self.state.acl_bad.add(block.acl)
            self.ledger.unparsed(n, exc.reason)

    def _inherited_child(self, n: int, tokens: list[str], block: _Block) -> None:
        self._collect_refs(tokens)
        if block.classification in ("unparsed", "out-of-scope"):
            self.ledger.unparsed(
                n,
                block.reason,
                relevant=block.relevant,
                classification="unparsed" if block.classification == "unparsed" else "out-of-scope",
            )
        else:
            self.ledger.mark(n, block.classification, relevant=block.relevant, reason=block.reason)

    def _collect_refs(self, tokens: list[str]) -> None:
        """ACL names referenced by route-maps, crypto maps, class-maps and distribute-lists."""
        refs = self.state.nonpolicy_refs
        kw = [t.lower() for t in tokens]
        if kw[:3] == ["match", "ip", "address"] and "prefix-list" not in kw:
            refs.update(tokens[3:])
        elif kw[:2] == ["match", "address"]:
            refs.update(tokens[2:])
        elif kw[:2] == ["match", "access-group"]:
            refs.add(tokens[3] if kw[2:3] == ["name"] and len(tokens) > 3 else tokens[-1])
        elif (
            kw[:1] == ["distribute-list"]
            and len(tokens) > 1
            and tokens[1] not in ("prefix", "gateway", "route-map")
        ):
            refs.add(tokens[1])

    # -- interface -------------------------------------------------------

    def _interface_child(self, n: int, tokens: list[str], st: fin.IosIface) -> None:
        kw = tokens[0].lower()
        if kw == "description":
            st.description = " ".join(tokens[1:])
            self.ledger.mark(n, "migrated", relevant=False)
        elif kw == "ip" and len(tokens) >= 2:
            self._interface_ip(n, tokens, st)
        elif kw == "ipv6":
            raise Unsupported("ipv6")
        elif kw == "zone-member":
            raise Unsupported("zone-based-firewall")
        elif kw == "crypto":
            self.ledger.unparsed(
                n, "vpn-not-migrated", relevant=False, classification="out-of-scope"
            )
        elif kw == "service-policy":
            self.ledger.unparsed(
                n, "qos-not-modelled", relevant=False, classification="out-of-scope"
            )
        elif kw in tables.IFACE_SAFE:
            self.ledger.mark(n, "not-policy")
        else:
            raise Unsupported("unrecognized-interface-command")

    def _interface_ip(self, n: int, tokens: list[str], st: fin.IosIface) -> None:
        sub = tokens[1].lower()
        if sub == "address":
            if len(tokens) == 4 and looks_like_ipv4(tokens[2]):
                st.ip = _interface_address(tokens[2], tokens[3])
                self.ledger.mark(n, "migrated", relevant=True)
            elif len(tokens) == 5 and tokens[4].lower() == "secondary":
                raise Unsupported("secondary-address")
            elif len(tokens) >= 3 and tokens[2].lower() in ("dhcp", "negotiated"):
                raise Unsupported("dynamic-interface-address")
            else:
                raise Unsupported("bad-ip-address")
        elif sub == "access-group":
            if len(tokens) != 4 or tokens[3].lower() not in ("in", "out"):
                raise Unsupported("bad-access-group")
            self.state.raw_bind.append((n, st.hw, tokens[2], tokens[3].lower()))
        elif sub in tables.IP_RELEVANT:
            raise Unsupported(tables.IP_RELEVANT[sub])
        elif sub in tables.IFACE_IP_SAFE:
            self.ledger.mark(n, "not-policy")
        else:
            raise Unsupported("unrecognized-interface-command")

    # -- ACL bodies ------------------------------------------------------

    def _acl_child(self, n: int, tokens: list[str], block: _Block) -> None:
        seq: int | None = None
        if tokens[0].isdigit():
            seq = int(tokens[0])
            tokens = tokens[1:]
            if not tokens:
                raise Unsupported("bad-acl-entry")
        self._acl_entry(n, block.acl, block.standard, tokens, seq)

    def _acl_entry(
        self, n: int, acl: str, standard: bool, tokens: list[str], seq: int | None
    ) -> None:
        kw = tokens[0].lower()
        if kw == "remark":
            self.pending_remark.setdefault(acl, []).append(" ".join(tokens[1:]))
            self.state.acl_lines[acl].append(n)
            self.ledger.mark(n, "migrated", relevant=False)
            return
        ordinal = self.ordinals.get(acl, 0) + 1
        self.ordinals[acl] = ordinal
        self.state.acl_lines[acl].append(n)
        remark = " ".join(self.pending_remark.pop(acl, []))[:1023]
        try:
            if kw in ("evaluate", "reflect"):
                raise Unsupported("reflexive-acl")
            if kw == "dynamic":
                raise Unsupported("lock-and-key")
            if seq is not None:
                if seq <= self.last_seq.get(acl, 0):
                    raise Unsupported("acl-sequence-out-of-order")
                self.last_seq[acl] = seq
            ace = parse_ios_ace(tokens, standard=standard)
        except Unsupported:
            self.state.acl_bad.add(acl)
            raise
        self.state.acls[acl].append(
            Rule(
                id=f"{acl}#{ordinal}",
                action=ace.action,
                match=ace.match,
                remark=remark,
                time_range=ace.time_range,
                vendor_seq=seq,
                log=ace.log,
                source_line=n,
            )
        )
        self.ledger.mark(n, "migrated", relevant=True)

    # -- vty -------------------------------------------------------------

    def _vty_child(self, n: int, tokens: list[str], vty: fin.IosVty) -> None:
        kw = tokens[0].lower()
        if kw == "access-class":
            if len(tokens) < 3 or tokens[2].lower() != "in":
                raise Unsupported("vty-access-class-direction")
            vty.acl = (n, tokens[1])
            self.state.mgmt_refs.add(tokens[1])
            self.ledger.mark(n, "management-plane", relevant=True)
        elif kw == "transport" and len(tokens) >= 3 and tokens[1].lower() == "input":
            for word in tokens[2:]:
                p = word.lower()
                if p == "all":
                    vty.transports.extend(["telnet", "ssh"])
                elif p != "none":
                    vty.transports.append(p)
            self.ledger.mark(n, "management-plane", relevant=True)
        elif kw == "ipv6":
            raise Unsupported("ipv6")
        else:
            self.ledger.mark(n, "not-policy")

    # ------------------------------------------------------------------
    # Top-level statements
    # ------------------------------------------------------------------

    def _cmd_version(self, n: int, tokens: list[str]) -> None:
        if len(tokens) != 2:
            raise Unsupported("unrecognized-command")
        if not self.os_version:
            self.os_version = tokens[1]
        self.ledger.mark(n, "not-policy")

    def _cmd_interface(self, n: int, tokens: list[str]) -> None:
        sub_ok = len(tokens) == 3 and tokens[2] in ("point-to-point", "multipoint")
        if len(tokens) == 2 or sub_ok:
            st = fin.IosIface(hw=tokens[1], line=n)
            self.state.ifaces.append(st)
            self.ledger.mark(n, "migrated", relevant=False)
            self.block = _Block("interface", iface=st)
        else:
            raise Unsupported("unrecognized-interface-command")

    def _cmd_access_list(self, n: int, tokens: list[str]) -> None:
        if len(tokens) < 3 or not tokens[1].isdigit():
            raise Unsupported("unsupported-acl-number")
        standard = _acl_is_standard(int(tokens[1]))
        if standard is None:
            raise Unsupported("unsupported-acl-number")
        acl = str(int(tokens[1]))
        self.state.acls.setdefault(acl, [])
        self.state.acl_lines.setdefault(acl, [])
        self._acl_entry(n, acl, standard, tokens[2:], None)

    def _cmd_ip(self, n: int, tokens: list[str]) -> None:
        sub = tokens[1].lower() if len(tokens) > 1 else ""
        if sub == "access-list":
            self._cmd_named_acl(n, tokens)
        elif sub == "route":
            self._cmd_route(n, tokens)
        elif sub == "http":
            if len(tokens) == 4 and tokens[2].lower() == "access-class":
                self.state.mgmt_refs.add(tokens[3])
                self.ledger.mark(n, "management-plane", relevant=True)
            elif [t.lower() for t in tokens[2:]] == ["server"]:
                self.state.http_lines.append(n)  # plain HTTP management, no TLS
                self.ledger.mark(n, "management-plane", relevant=True)
            else:
                self.ledger.mark(n, "management-plane", relevant=False)
        elif sub == "nat":
            low = [t.lower() for t in tokens]
            if "list" in low and low.index("list") + 1 < len(tokens):
                self.state.nonpolicy_refs.add(tokens[low.index("list") + 1])
            self.ledger.mark(n, "not-policy", reason="nat")
        elif sub in tables.IP_RELEVANT:
            raise Unsupported(tables.IP_RELEVANT[sub])
        elif sub in tables.IP_SAFE:
            self.ledger.mark(n, "not-policy")
        else:
            raise Unsupported("unrecognized-command")

    def _cmd_named_acl(self, n: int, tokens: list[str]) -> None:
        kind = tokens[2].lower() if len(tokens) > 2 else ""
        if kind in ("extended", "standard") and len(tokens) == 4:
            acl = tokens[3]
            self.state.acls.setdefault(acl, [])
            self.state.acl_lines.setdefault(acl, []).append(n)
            self.ledger.mark(n, "migrated", relevant=False)
            self.block = _Block("acl", acl=acl, standard=kind == "standard")
        elif kind in ("resequence", "logging", "log-update", "persistent"):
            self.ledger.mark(n, "not-policy")
        else:
            raise Unsupported("unrecognized-command")

    def _cmd_route(self, n: int, tokens: list[str]) -> None:
        if tokens[2:3] and tokens[2].lower() == "vrf":
            raise Unsupported("vrf-route")
        if len(tokens) < 5:
            raise Unsupported("bad-route")
        try:
            network = ipaddress.IPv4Network(f"{tokens[2]}/{parse_subnet_mask(tokens[3])}", False)
        except ValueError:
            raise Unsupported("bad-route") from None
        next_hop: ipaddress.IPv4Address | None = None
        iface = ""
        distance = 1
        rest = tokens[4:]
        i = 0
        while i < len(rest):
            tok = rest[i]
            low = tok.lower()
            if looks_like_ipv4(tok):
                next_hop = ipaddress.IPv4Address(tok)
            elif tok.isdigit():
                distance = int(tok)
            elif low in ("name", "tag"):
                i += 1
            elif low == "permanent":
                pass
            elif low in ("track", "global"):
                raise Unsupported("route-track" if low == "track" else "vrf-route")
            elif not iface and next_hop is None:
                iface = tok
            else:
                raise Unsupported("route-option-unsupported")
            i += 1
        if not iface and next_hop is None:
            raise Unsupported("bad-route")
        self.state.raw_routes.append(fin.RawRoute(n, network, next_hop, iface, distance))

    def _cmd_line(self, n: int, tokens: list[str]) -> None:
        if len(tokens) > 1 and tokens[1].lower() == "vty":
            vty = fin.IosVty(n)
            self.state.vtys.append(vty)
            self.ledger.mark(n, "management-plane", relevant=False)
            self.block = _Block("vty", vty=vty)
        else:
            self._inherit(n, "not-policy", "console-line")

    def _cmd_snmp(self, n: int, tokens: list[str]) -> None:
        if len(tokens) > 2 and tokens[1].lower() == "community":
            low = [t.lower() for t in tokens]
            idx = next((i for i, t in enumerate(low) if t in ("ro", "rw")), -1)
            acl = tokens[idx + 1] if 0 <= idx < len(tokens) - 1 and low[idx + 1] != "ipv6" else ""
            if acl:
                self.state.mgmt_refs.add(acl)
            self.state.snmp.append((n, acl))
            self.ledger.mark(n, "management-plane", relevant=True)
        else:
            self.ledger.mark(n, "management-plane", relevant=False)

    def _cmd_ntp(self, n: int, tokens: list[str]) -> None:
        if len(tokens) > 3 and tokens[1].lower() == "access-group":
            self.state.mgmt_refs.add(tokens[-1])
            self.ledger.mark(n, "management-plane", relevant=True)
        else:
            self.ledger.mark(n, "not-policy")

    def _cmd_banner(self, n: int, tokens: list[str]) -> None:
        self.ledger.mark(n, "not-policy", reason="banner")
        parts = self.lines[n - 1].split(None, 2)
        if len(parts) == 3 and parts[2]:
            delim = parts[2][0]
            if parts[2].count(delim) < 2:
                self.banner_delim = delim

    def _cmd_router(self, n: int, tokens: list[str]) -> None:
        self._inherit(n, "out-of-scope", "dynamic-routing")

    def _cmd_distribute_list(self, n: int, tokens: list[str]) -> None:
        self._collect_refs(tokens)
        self.ledger.mark(n, "not-policy", reason="distribute-list")

    def _cmd_route_map(self, n: int, tokens: list[str]) -> None:
        self._inherit(n, "not-policy", "route-map")

    def _cmd_crypto(self, n: int, tokens: list[str]) -> None:
        self._inherit(n, "out-of-scope", "vpn-not-migrated")

    def _cmd_qos(self, n: int, tokens: list[str]) -> None:
        if "inspect" in [t.lower() for t in tokens]:
            raise Unsupported("zone-based-firewall")
        self._inherit(n, "out-of-scope", "qos-not-modelled")

    def _cmd_object_group(self, n: int, tokens: list[str]) -> None:
        self._inherit(n, "out-of-scope", "ios-object-group")

    def _cmd_control_plane(self, n: int, tokens: list[str]) -> None:
        self._inherit(n, "not-policy", "control-plane")

    def _cmd_no(self, n: int, tokens: list[str]) -> None:
        self.ledger.mark(n, "not-policy", reason="no-command")


def _interface_address(addr: str, mask: str) -> ipaddress.IPv4Interface:
    try:
        return ipaddress.IPv4Interface(f"{addr}/{parse_subnet_mask(mask)}")
    except ValueError:
        raise Unsupported("bad-ip-address") from None


def parse_ios(text: str, *, os_version: str = "") -> Policy:
    """Parse already-redacted IOS config text. Callers must run ``necro.redact.redact`` first."""
    return _IosParser(text, os_version).parse()
