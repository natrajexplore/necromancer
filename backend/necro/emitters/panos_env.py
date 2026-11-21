"""The shared state of one PAN-OS emission: the source policy and what the builders find out."""

from __future__ import annotations

from dataclasses import dataclass, field

from necro.emitters.panos_network import ZoneMap
from necro.ir import Action, Context, Dialect, Policy
from necro.ledger import LedgerEntry
from necro.nat import NatModel
from necro.sets import AddrSet, PortSet
from necro.zones import RouteTable

ANY_ZONE = "any"


@dataclass(frozen=True)
class RuleSpec:
    """One PAN-OS security rule, before names are allocated and objects are created."""

    key: str  # unique per rule: drives the PAN-OS rule name
    source: str  # source rule id (``acl#seq``) or an implicit rule id
    from_zone: str
    to_zone: str
    src: AddrSet
    dst: AddrSet
    proto: int | None
    sport: PortSet
    dport: PortSet
    icmp_types: frozenset[int] | None
    action: Action
    disabled: bool = False
    remark: str = ""
    tags: tuple[str, ...] = ()
    log_start: bool = False


@dataclass
class BuildEnv:
    """What building needs: the source policy, zone names, routes, and what could not be said."""

    policy: Policy
    zones: ZoneMap
    routes: RouteTable
    device: AddrSet  # every address the device owns
    nat: NatModel
    nat_control: bool  # PIX always enforces it; ASA only when configured (policy-semantics 1.5)
    unsupported: list[str] = field(default_factory=list)  # not expressed (blocks the verdict)
    notes: list[str] = field(default_factory=list)  # expressed differently, no decision changes
    ledger: list[LedgerEntry] = field(default_factory=list)  # expressed lossily, on the record

    def ingress(self, ctx: Context) -> str | None:
        """The nameif NAT rules are keyed by, or None where NAT does not apply (IOS)."""
        return None if self.policy.dialect == Dialect.ios else ctx.interface
