"""Vendor-neutral policy IR (pydantic v2 models).

All parsers produce these models; all emitters consume them.
No parser output leaves the parser as raw text; no emitter reads raw config.
"""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from necro.sets import AddrSet, PortSet

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Action(StrEnum):
    permit = "permit"
    deny = "deny"


class AddressSpace(StrEnum):
    """The address space ACLs are written in for a given config."""

    mapped = "mapped"  # PIX 6.x and ASA <= 8.2: global/mapped addresses
    real = "real"  # ASA >= 8.3: real (pre-NAT) addresses
    as_is = "as-is"  # IOS: no NAT translation concern for ACLs


class PolicyMode(StrEnum):
    routed = "routed"
    transparent = "transparent"
    multiple = "multiple"  # multi-context (out of scope)
    unknown = "unknown"


class Dialect(StrEnum):
    pix = "pix"
    asa = "asa"
    ios = "ios"


class NatType(StrEnum):
    static = "static"
    dynamic = "dynamic"
    pat = "pat"
    nat0 = "nat0"


class LedgerClass(StrEnum):
    tightening = "tightening"
    stateful_established = "stateful-established"
    time_range = "time-range"
    to_the_box = "to-the-box"
    zone_any = "zone-any"
    app_id_protocol = "app-id-protocol"
    outbound_acl = "outbound-acl"
    waived_unparsed = "waived-unparsed"


# ---------------------------------------------------------------------------
# Match: the 5-tuple selector for a rule
# ---------------------------------------------------------------------------


class Match(BaseModel):
    """The match criteria for a single ACE."""

    src: AddrSet = Field(default_factory=AddrSet.any)
    dst: AddrSet = Field(default_factory=AddrSet.any)
    proto: int | None = None  # IP protocol number; None means any
    src_ports: PortSet = Field(default_factory=PortSet.any)
    dst_ports: PortSet = Field(default_factory=PortSet.any)
    icmp_types: frozenset[int] | None = None  # None means any type
    established: bool = False  # IOS TCP established flag

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


class Rule(BaseModel):
    """One ACE translated into vendor-neutral form."""

    id: str  # "<acl-name>#<seq>" (1-based ordinal, remarks not counted)
    action: Action
    match: Match
    inactive: bool = False  # inactive keyword in original ACE
    remark: str = ""  # from preceding remark line, <= 1023 chars
    time_range: str = ""  # name of the time-range object (if any)
    vendor_seq: int | None = None  # IOS named-ACL sequence number
    log: bool = False
    log_level: str = ""

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Interface / Route / Binding
# ---------------------------------------------------------------------------


class Interface(BaseModel):
    """An interface with a nameif, security level and IP address."""

    hw_name: str = ""  # hardware name e.g. GigabitEthernet0/0
    nameif: str = ""  # logical name used in ACLs and NAT
    security_level: int = 0  # 0-100; higher is more trusted
    ip_address: ipaddress.IPv4Interface | None = None
    description: str = ""

    model_config = {"arbitrary_types_allowed": True}


class Route(BaseModel):
    """A static route entry."""

    network: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address | None = None  # None for connected / null0
    interface: str = ""  # outgoing interface nameif
    metric: int = 1

    model_config = {"arbitrary_types_allowed": True}


class Binding(BaseModel):
    """An access-group binding: ACL attached to an interface in a direction."""

    acl_name: str
    interface: str  # nameif
    direction: Literal["in", "out"]
    global_acl: bool = False  # True for access-group X global (ASA 8.3+)


# ---------------------------------------------------------------------------
# NAT rule
# ---------------------------------------------------------------------------


class NatRule(BaseModel):
    """Pre-8.3 static/nat/global or 8.3+ object/twice-NAT entry."""

    nat_type: NatType
    real_interface: str = ""
    mapped_interface: str = ""
    real_addr: AddrSet = Field(default_factory=AddrSet)
    mapped_addr: AddrSet = Field(default_factory=AddrSet)
    real_ports: PortSet = Field(default_factory=PortSet)
    mapped_ports: PortSet = Field(default_factory=PortSet)
    proto: int | None = None  # 6=TCP, 17=UDP, None=any
    nat_id: int | None = None  # nat (inside) <id> pool identifier
    is_pat: bool = False
    no_proxy_arp: bool = False
    description: str = ""

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Management access
# ---------------------------------------------------------------------------


class MgmtAccess(BaseModel):
    """telnet / ssh / http / icmp / snmp-server host management-plane entry."""

    proto: str  # "telnet", "ssh", "http", "icmp", "snmp"
    src_addr: AddrSet = Field(default_factory=AddrSet.any)
    interface: str = ""  # nameif the rule applies to
    version: str = ""  # SSH version, SNMP version, etc.

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Line record
# ---------------------------------------------------------------------------


class LineRecord(BaseModel):
    """Classification of one source config line."""

    line_no: int
    text: str
    classification: Literal[
        "migrated",
        "not-policy",
        "management-plane",
        "out-of-scope",
        "unparsed",
    ]
    security_relevant: bool = False
    waiver_id: str = ""


# ---------------------------------------------------------------------------
# Flow: a single test packet
# ---------------------------------------------------------------------------


class Flow(BaseModel):
    """A test packet for the evaluator."""

    src: ipaddress.IPv4Address
    dst: ipaddress.IPv4Address
    proto: int  # IP protocol number
    src_port: int = 0
    dst_port: int = 0
    icmp_type: int | None = None
    established: bool = False  # IOS TCP established flag

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


class Decision(BaseModel):
    """The result of evaluating a flow against a policy context."""

    action: Action
    rule_id: str  # e.g. "OUTSIDE_IN#3" or "implicit-deny"
    to_zone: str = ""  # egress interface nameif, "self", or "any"
    reason: str = ""  # extra detail for implicit decisions


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


class Context(BaseModel):
    """One ingress-interface policy context (name = '<nameif>:in')."""

    name: str
    interface: str  # nameif
    acl_name: str = ""  # empty means no ACL bound (security-level logic applies)
    global_acl_name: str = ""  # ASA 8.3+ global ACL, if any
    egress_acl_name: str = ""  # access-group out ACL, if any
    address_space: AddressSpace = AddressSpace.as_is


# ---------------------------------------------------------------------------
# Policy: the top-level container
# ---------------------------------------------------------------------------


class Policy(BaseModel):
    """Everything parsed from one config file."""

    dialect: Dialect = Dialect.asa
    os_version: str = ""  # e.g. "8.2(5)"
    mode: PolicyMode = PolicyMode.routed
    address_space: AddressSpace = AddressSpace.mapped

    # name aliases: name <ip> <label>
    name_aliases: dict[str, str] = Field(default_factory=dict)  # label -> ip string

    interfaces: list[Interface] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    bindings: list[Binding] = Field(default_factory=list)

    # ACL name -> ordered list of Rules
    acls: dict[str, list[Rule]] = Field(default_factory=dict)

    nat_rules: list[NatRule] = Field(default_factory=list)
    nat_control: bool = False  # ASA only; PIX always enforces it

    mgmt_access: list[MgmtAccess] = Field(default_factory=list)
    line_records: list[LineRecord] = Field(default_factory=list)

    # Global config flags
    same_security_inter: bool = False  # same-security-traffic permit inter-interface
    same_security_intra: bool = False  # same-security-traffic permit intra-interface

    input_sha256: str = ""

    model_config = {"arbitrary_types_allowed": True}
