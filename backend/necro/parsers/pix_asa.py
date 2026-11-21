"""PIX 6.x / ASA 7.x-8.2 parser: redacted config text -> Policy IR (requirements 1.1, 1.4, 1.5).

The walk is line-oriented. Statements that depend on the whole file (object-group expansion, ACE
operands, access-group, routes, interface addresses) are collected first and resolved afterwards, so
order in the file never matters. Every line is classified exactly once through ``LineLedger``.

ASA 8.3+ constructs (``object network``, object NAT, ``any4`` operands in objects, ...) are Phase 2
and become security-relevant unparsed lines; they are never skipped silently.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

from necro.ir import (
    AddressSpace,
    Dialect,
    Interface,
    MgmtAccess,
    NatRule,
    Policy,
    PolicyMode,
    Route,
)
from necro.parsers import pix_asa_stmts as stmts
from necro.parsers.cisco_common import (
    Classification,
    LineLedger,
    Unsupported,
    is_comment_or_blank,
    is_indented,
    split_lines,
    version_at_least,
)
from necro.parsers.cisco_groups import (
    KIND_ICMP,
    KIND_NETWORK,
    KIND_PROTOCOL,
    KIND_SERVICE,
    KIND_SERVICE_MULTI,
    GroupTable,
)
from necro.parsers.pix_asa_finish import (
    IfaceState,
    RawAce,
    build_acls,
    finish_bindings,
    finish_interfaces,
    finish_routes,
    interface_address,
)
from necro.parsers.pix_asa_tables import (
    IFACE_CHILD_NOT_POLICY,
    INSPECTION,
    NOT_POLICY,
    PIX_HW_ATTRS,
    RELEVANT_UNSUPPORTED,
    VPN,
)

_Handler = Callable[[int, list[str]], None]


@dataclass
class _Block:
    kind: str  # "interface" | "group" | "inherit"
    iface: IfaceState | None = None
    group: str = ""
    classification: Classification = "not-policy"
    relevant: bool = False
    reason: str = ""


class _PixAsaParser:
    def __init__(self, text: str, dialect: Dialect, os_version: str) -> None:
        self.text = text
        self.lines = split_lines(text)
        self.ledger = LineLedger(self.lines)
        self.dialect = dialect
        self.os_version = os_version
        self.mode = PolicyMode.routed
        self.names: dict[str, str] = {}
        self.groups = GroupTable()
        self.ifaces: list[IfaceState] = []
        self.by_hw: dict[str, IfaceState] = {}
        self.pending_ip: list[tuple[int, str, str, str]] = []
        self.raw_acl: list[RawAce] = []
        self.raw_bind: list[tuple[int, list[str]]] = []
        self.raw_routes: list[tuple[int, Route]] = []
        self.nat_rules: list[NatRule] = []
        self.mgmt: list[MgmtAccess] = []
        self.nat_control = False
        self.same_inter = False
        self.same_intra = False
        self.block: _Block | None = None
        self.handlers: dict[str, _Handler] = {
            "pix": self._cmd_version,
            "asa": self._cmd_version,
            "names": self._cmd_names,
            "name": self._cmd_name,
            "nameif": self._cmd_nameif,
            "interface": self._cmd_interface,
            "ip": self._cmd_ip,
            "route": self._cmd_route,
            "object-group": self._cmd_object_group,
            "access-list": self._cmd_access_list,
            "access-group": self._cmd_access_group,
            "same-security-traffic": self._cmd_same_security,
            "nat-control": self._cmd_nat_control,
            "no": self._cmd_no,
            "nat": self._cmd_nat,
            "global": self._cmd_global,
            "static": self._cmd_static,
            "telnet": self._cmd_mgmt,
            "ssh": self._cmd_mgmt,
            "http": self._cmd_mgmt,
            "icmp": self._cmd_icmp,
            "snmp-server": self._cmd_snmp,
            "firewall": self._cmd_firewall,
            "mode": self._cmd_mode,
            "context": self._cmd_context,
        }

    # ------------------------------------------------------------------
    # Driver
    # ------------------------------------------------------------------

    def parse(self) -> Policy:
        self._prescan_names()
        for n, line in enumerate(self.lines, 1):
            self._walk_line(n, line)
        self.groups.resolve(self.names, self.ledger)
        acls = build_acls(self.raw_acl, self.names, self.groups, self.ledger)
        interfaces = finish_interfaces(self.ifaces, self.pending_ip, self.ledger)
        routes = finish_routes(self.raw_routes, interfaces, self.ledger)
        bindings, egress = finish_bindings(self.raw_bind, acls, interfaces, self.ledger)
        records, unparsed = self.ledger.finalize()
        space = AddressSpace.mapped
        if self.dialect == Dialect.asa and version_at_least(self.os_version, 8, 3):
            space = AddressSpace.real
        return Policy(
            dialect=self.dialect,
            os_version=self.os_version,
            mode=self.mode,
            address_space=space,
            name_aliases=dict(self.names),
            interfaces=interfaces,
            routes=routes,
            bindings=bindings,
            object_groups=self.groups.info(),
            acls=acls,
            egress_acls=egress,
            nat_rules=self.nat_rules,
            nat_control=self.nat_control,
            mgmt_access=self.mgmt,
            line_records=records,
            unparsed=unparsed,
            same_security_inter=self.same_inter,
            same_security_intra=self.same_intra,
            input_sha256=hashlib.sha256(self.text.encode("utf-8")).hexdigest(),
        )

    def _prescan_names(self) -> None:
        """``name`` aliases are needed by every other statement, wherever they appear."""
        for line in self.lines:
            tokens = line.split()
            if len(tokens) >= 3 and not is_indented(line) and tokens[0].lower() == "name":
                try:
                    self.names[tokens[2]] = str(ipaddress.IPv4Address(tokens[1]))
                except ValueError:
                    continue

    def _walk_line(self, n: int, line: str) -> None:
        if is_comment_or_blank(line):
            self.ledger.mark(n, "not-policy")
            return
        tokens = line.split()
        if is_indented(line):
            self._child_line(n, tokens)
            return
        self.block = None
        kw = tokens[0].lower()
        handler = self.handlers.get(kw)
        try:
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
        if kw in NOT_POLICY:
            self.ledger.mark(n, "not-policy")
            self.block = _Block("inherit")
        elif kw in INSPECTION:
            self.ledger.unparsed(
                n, "inspection-engine-not-modelled", relevant=False, classification="out-of-scope"
            )
            self.block = _Block(
                "inherit", classification="out-of-scope", reason="inspection-engine-not-modelled"
            )
        elif kw in VPN:
            self.ledger.unparsed(
                n, "vpn-not-migrated", relevant=False, classification="out-of-scope"
            )
            self.block = _Block("inherit", classification="out-of-scope", reason="vpn-not-migrated")
        elif kw in RELEVANT_UNSUPPORTED:
            raise Unsupported(RELEVANT_UNSUPPORTED[kw])
        else:
            raise Unsupported("unrecognized-command")

    # ------------------------------------------------------------------
    # Indented lines
    # ------------------------------------------------------------------

    def _child_line(self, n: int, tokens: list[str]) -> None:
        block = self.block
        if block is None:
            self.ledger.unparsed(n, "orphan-indented-line")
        elif block.kind == "group":
            self.groups.add_member(block.group, n, tokens)
        elif block.kind == "interface" and block.iface is not None:
            try:
                self._interface_child(n, tokens, block.iface)
            except Unsupported as exc:
                self.ledger.unparsed(n, exc.reason)
        elif block.classification in ("unparsed", "out-of-scope"):
            self.ledger.unparsed(
                n,
                block.reason,
                relevant=block.relevant,
                classification="unparsed" if block.classification == "unparsed" else "out-of-scope",
            )
        else:
            self.ledger.mark(n, block.classification, relevant=block.relevant, reason=block.reason)

    def _interface_child(self, n: int, tokens: list[str], st: IfaceState) -> None:
        kw = tokens[0].lower()
        if kw == "nameif" and len(tokens) == 2:
            st.iface.nameif = tokens[1]
            st.nameif_line = n
            self.ledger.mark(n, "migrated", relevant=True)
        elif kw == "security-level" and len(tokens) == 2 and tokens[1].isdigit():
            level = int(tokens[1])
            if level > 100:
                raise Unsupported("security-level-out-of-range")
            st.iface.security_level = level
            st.level_seen = True
            self.ledger.mark(n, "migrated", relevant=True)
        elif kw == "ip" and len(tokens) >= 2 and tokens[1].lower() == "address":
            if len(tokens) < 4 or tokens[2].lower() in ("dhcp", "pppoe"):
                raise Unsupported("dynamic-interface-address")
            if len(tokens) not in (4, 6) or (len(tokens) == 6 and tokens[4] != "standby"):
                raise Unsupported("bad-ip-address")
            st.iface.ip_address = interface_address(tokens[2], tokens[3])
            self.ledger.mark(n, "migrated", relevant=True)
        elif kw == "description":
            st.iface.description = " ".join(tokens[1:])
            self.ledger.mark(n, "migrated", relevant=False)
        elif kw in IFACE_CHILD_NOT_POLICY:
            self.ledger.mark(n, "not-policy")
        else:
            raise Unsupported("unknown-interface-command")

    # ------------------------------------------------------------------
    # Top-level statements
    # ------------------------------------------------------------------

    def _cmd_version(self, n: int, tokens: list[str]) -> None:
        if len(tokens) < 3 or tokens[1].lower() != "version":
            raise Unsupported("unrecognized-command")
        if not self.os_version:
            self.os_version = tokens[2]
        self.ledger.mark(n, "not-policy")

    def _cmd_names(self, n: int, tokens: list[str]) -> None:
        self.ledger.mark(n, "migrated", relevant=False)

    def _cmd_name(self, n: int, tokens: list[str]) -> None:
        if len(tokens) < 3 or self.names.get(tokens[2]) != tokens[1]:
            raise Unsupported("bad-name-alias")
        self.ledger.mark(n, "migrated", relevant=True)

    def _state_for(self, hw: str, n: int) -> IfaceState:
        st = self.by_hw.get(hw)
        if st is None:
            st = IfaceState(Interface(hw_name=hw, source_line=n), n)
            self.by_hw[hw] = st
            self.ifaces.append(st)
        return st

    def _cmd_nameif(self, n: int, tokens: list[str]) -> None:
        """PIX 6.x: ``nameif <hw> <name> security<N>``."""
        if len(tokens) != 4 or not tokens[3].lower().startswith("security"):
            raise Unsupported("bad-nameif")
        level_text = tokens[3][len("security") :]
        if not level_text.isdigit() or int(level_text) > 100:
            raise Unsupported("bad-nameif")
        st = self._state_for(tokens[1], n)
        st.iface.nameif = tokens[2]
        st.iface.security_level = int(level_text)
        st.level_seen = True
        st.nameif_line = n
        self.ledger.mark(n, "migrated", relevant=True)

    def _cmd_interface(self, n: int, tokens: list[str]) -> None:
        if len(tokens) == 2:
            st = self._state_for(tokens[1], n)
            self.ledger.mark(n, "migrated", relevant=False)
            self.block = _Block("interface", iface=st)
        elif len(tokens) == 3 and tokens[2].lower() in PIX_HW_ATTRS:
            self.ledger.mark(n, "not-policy", reason="pix-hardware-attribute")
        else:
            raise Unsupported("unrecognized-interface-command")

    def _cmd_ip(self, n: int, tokens: list[str]) -> None:
        sub = tokens[1].lower() if len(tokens) > 1 else ""
        if sub == "address":
            if len(tokens) < 5:
                raise Unsupported("bad-ip-address")
            self.pending_ip.append((n, tokens[2], tokens[3], tokens[4]))
        elif sub in ("local", "audit"):
            self.ledger.mark(n, "not-policy")
        else:
            raise Unsupported("unrecognized-command")

    def _cmd_route(self, n: int, tokens: list[str]) -> None:
        self.raw_routes.append((n, stmts.parse_route(tokens, self.names)))

    def _cmd_object_group(self, n: int, tokens: list[str]) -> None:
        if len(tokens) < 3:
            raise Unsupported("bad-object-group")
        what, name = tokens[1].lower(), tokens[2]
        port_proto = ""
        if what == "network":
            kind = KIND_NETWORK
        elif what == "service" and len(tokens) == 3:
            kind = KIND_SERVICE_MULTI
        elif (
            what == "service"
            and len(tokens) == 4
            and tokens[3].lower()
            in (
                "tcp",
                "udp",
                "tcp-udp",
            )
        ):
            kind, port_proto = KIND_SERVICE, tokens[3].lower()
        elif what == "protocol":
            kind = KIND_PROTOCOL
        elif what == "icmp-type":
            kind = KIND_ICMP
        elif what == "user":
            raise Unsupported("identity-firewall")
        elif what == "security":
            raise Unsupported("trustsec-security-group")
        else:
            raise Unsupported("unknown-object-group-type")
        if not self.groups.define(name, kind, port_proto, n):
            raise Unsupported("object-group-kind-redefined")
        self.ledger.mark(n, "migrated", relevant=True)
        self.block = _Block("group", group=name)

    def _cmd_access_list(self, n: int, tokens: list[str]) -> None:
        if len(tokens) < 3:
            raise Unsupported("malformed-access-list")
        acl, sub = tokens[1], tokens[2].lower()
        if acl.lower() == "compiled":
            self.ledger.mark(n, "not-policy")
        elif sub == "remark":
            self.raw_acl.append(RawAce(n, acl, [], " ".join(tokens[3:])))
        elif sub == "line":
            raise Unsupported("acl-line-insertion")
        elif sub == "standard":
            self.ledger.mark(n, "not-policy", reason="asa-standard-acl")
        elif sub in ("ethertype", "webtype"):
            raise Unsupported(f"{sub}-acl")
        else:
            body = tokens[3:] if sub == "extended" else tokens[2:]
            self.raw_acl.append(RawAce(n, acl, body))

    def _cmd_access_group(self, n: int, tokens: list[str]) -> None:
        self.raw_bind.append((n, tokens))

    def _cmd_same_security(self, n: int, tokens: list[str]) -> None:
        if len(tokens) == 3 and tokens[1].lower() == "permit":
            if tokens[2].lower() == "inter-interface":
                self.same_inter = True
            elif tokens[2].lower() == "intra-interface":
                self.same_intra = True
            else:
                raise Unsupported("bad-same-security-traffic")
            self.ledger.mark(n, "migrated", relevant=True)
        else:
            raise Unsupported("bad-same-security-traffic")

    def _cmd_nat_control(self, n: int, tokens: list[str]) -> None:
        self.nat_control = True
        self.ledger.mark(n, "migrated", relevant=True)

    def _cmd_no(self, n: int, tokens: list[str]) -> None:
        sub = tokens[1].lower() if len(tokens) > 1 else ""
        if sub == "nat-control":
            self.nat_control = False
            self.ledger.mark(n, "migrated", relevant=True)
        elif sub == "same-security-traffic" and len(tokens) == 4:
            if tokens[3].lower() == "inter-interface":
                self.same_inter = False
            elif tokens[3].lower() == "intra-interface":
                self.same_intra = False
            self.ledger.mark(n, "migrated", relevant=True)
        elif sub in RELEVANT_UNSUPPORTED:
            raise Unsupported(RELEVANT_UNSUPPORTED[sub])
        else:
            self.ledger.mark(n, "not-policy", reason="no-command")

    def _cmd_nat(self, n: int, tokens: list[str]) -> None:
        self.nat_rules.append(stmts.parse_nat(tokens, self.names))
        self.ledger.mark(n, "migrated", relevant=True)

    def _cmd_global(self, n: int, tokens: list[str]) -> None:
        self.nat_rules.append(stmts.parse_global(tokens, self.names))
        self.ledger.mark(n, "migrated", relevant=True)

    def _cmd_static(self, n: int, tokens: list[str]) -> None:
        self.nat_rules.append(stmts.parse_static(tokens, self.names))
        self.ledger.mark(n, "migrated", relevant=True)

    def _cmd_mgmt(self, n: int, tokens: list[str]) -> None:
        access = stmts.parse_mgmt(tokens, self.names)
        if access is None:
            self.ledger.mark(n, "management-plane", relevant=False)
        else:
            access.source_line = n
            self.mgmt.append(access)
            self.ledger.mark(n, "management-plane", relevant=True)

    def _cmd_icmp(self, n: int, tokens: list[str]) -> None:
        access = stmts.parse_icmp_mgmt(tokens, self.names)
        if access is None:
            self.ledger.mark(n, "management-plane", relevant=False)
        else:
            access.source_line = n
            self.mgmt.append(access)
            self.ledger.mark(n, "management-plane", relevant=True)

    def _cmd_snmp(self, n: int, tokens: list[str]) -> None:
        if len(tokens) > 1 and tokens[1].lower() == "host":
            host = stmts.parse_snmp_host(tokens, self.names)
            host.source_line = n
            self.mgmt.append(host)
            self.ledger.mark(n, "management-plane", relevant=True)
        else:
            self.ledger.mark(n, "management-plane", relevant=False)

    def _cmd_firewall(self, n: int, tokens: list[str]) -> None:
        if len(tokens) == 2 and tokens[1].lower() == "transparent":
            self.mode = PolicyMode.transparent
            self.ledger.unparsed(
                n, "transparent-firewall-mode", relevant=True, classification="out-of-scope"
            )
        else:
            raise Unsupported("unrecognized-command")

    def _cmd_mode(self, n: int, tokens: list[str]) -> None:
        if len(tokens) == 2 and tokens[1].lower() == "multiple":
            self.mode = PolicyMode.multiple
            self.ledger.unparsed(
                n, "multiple-context-mode", relevant=True, classification="out-of-scope"
            )
        else:
            raise Unsupported("unrecognized-command")

    def _cmd_context(self, n: int, tokens: list[str]) -> None:
        self.mode = PolicyMode.multiple
        self.ledger.unparsed(
            n, "multiple-context-mode", relevant=True, classification="out-of-scope"
        )
        self.block = _Block(
            "inherit", classification="out-of-scope", relevant=True, reason="multiple-context-mode"
        )


def parse_pix_asa(text: str, *, dialect: Dialect = Dialect.asa, os_version: str = "") -> Policy:
    """Parse already-redacted PIX/ASA config text. Raises ``ParseError`` on cycles/undefined groups.

    Callers must run ``necro.redact.redact`` first (``necro.parsers.parse_config`` does).
    """
    return _PixAsaParser(text, dialect, os_version).parse()
