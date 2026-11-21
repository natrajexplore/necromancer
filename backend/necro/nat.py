"""NAT model and address-space mapping for nat-control enforcement.

Covers the pre-8.3 static/nat/global model.
Implements NatModel.translates() used by evaluate.py for nat-control checks.

Pre-8.3 semantics:
  static (real_if, mapped_if) mapped_addr real_addr [netmask mask]
    -> a flow arriving on mapped_if whose destination matches mapped_addr
       has a translation (to real_addr).
  nat (real_if) <id> real_net [mask]
    -> a flow sourced from real_if matching real_net has a translation
       (via the matching global pool for nat_id).
  global (mapped_if) <id> <pool_start>-<pool_end> [netmask mask]
    -> defines the mapped pool for nat_id.
  nat (real_if) 0 real_net
    -> nat exemption; flow does NOT need a translation even with nat-control.

Unsupported NAT forms (policy NAT with ACLs, twice NAT with service translation,
nat 0 access-list) are security-relevant unparsed lines; this model treats them
as not translated (conservative).

PBT P13 covers 8.3+ static NAT (task 10). This module covers the pre-8.3 model
needed by task 3.3.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from necro.ir import Flow, NatType, Policy
from necro.sets import AddrSet


@dataclass
class MappedSplit:
    """How the static NAT rules of one ingress interface treat a set of ACL destinations."""

    # (mapped addresses, the real addresses they translate to, real minus mapped as an integer)
    translated: list[tuple[AddrSet, AddrSet, int]] = field(default_factory=list)
    port_dependent: AddrSet = field(default_factory=AddrSet)
    untouched: AddrSet = field(default_factory=AddrSet)


class NatModel:
    """Pre-8.3 NAT model for nat-control enforcement."""

    def __init__(self, policy: Policy) -> None:
        self._nat_rules = policy.nat_rules

    def translation_space(self, ingress_interface: str) -> tuple[AddrSet, AddrSet]:
        """The sources and the destinations that have a translation for flows entering here.

        A flow is translated when its source is in the first set or its destination is in the
        second. ``translates`` is exactly that test, and the PAN-OS emitter uses the same two
        sets to reproduce nat-control (a rule may only permit what the source device translates):

          - nat 0 exemptions and dynamic/PAT rules on this (real) interface: their real addresses.
          - static rules: the mapped addresses when this is the mapped interface, and the real
            addresses when this is the real interface (the reverse direction).
        """
        sources = AddrSet()
        destinations = AddrSet()
        for rule in self._nat_rules:
            if rule.nat_type == NatType.static:
                if rule.mapped_interface == ingress_interface:
                    destinations = destinations.union(rule.mapped_addr)
                if rule.real_interface == ingress_interface:
                    destinations = destinations.union(rule.real_addr)
            elif (
                rule.nat_type in (NatType.nat0, NatType.dynamic, NatType.pat)
                and rule.real_interface == ingress_interface
            ):
                sources = sources.union(rule.real_addr)
        return sources, destinations

    def translates(self, ingress_interface: str, flow: Flow) -> bool:
        """Return True if the flow has a matching NAT translation.

        Called by evaluate.py when nat-control is active.
        """
        sources, destinations = self.translation_space(ingress_interface)
        return sources.contains(flow.src) or destinations.contains(flow.dst)

    def split_mapped(self, ingress_interface: str, addresses: AddrSet) -> MappedSplit:
        """Split ACL destination addresses by how ``map_destination`` treats them.

        Static rules are tried in order, like ``map_destination``. Addresses hit by a plain
        static are paired with the real addresses they translate to. Addresses hit by a port
        static depend on the flow's protocol and port, so no single real address applies.
        """
        split = MappedSplit()
        remaining = addresses
        for rule in self._nat_rules:
            if rule.nat_type != NatType.static or rule.mapped_interface != ingress_interface:
                continue
            hit = remaining.intersect(rule.mapped_addr)
            real_nets = rule.real_addr.to_networks()
            mapped_nets = rule.mapped_addr.to_networks()
            if hit.is_empty() or not real_nets or not mapped_nets:
                continue
            remaining = remaining.subtract(hit)
            if rule.proto is not None:
                split.port_dependent = split.port_dependent.union(hit)
                continue
            offset = int(real_nets[0].network_address) - int(mapped_nets[0].network_address)
            real = AddrSet([(iv.lo + offset, iv.hi + offset) for iv in hit.intervals])
            split.translated.append((hit, real, offset))
        split.untouched = remaining
        return split

    def map_destination(
        self,
        ingress_interface: str,
        dst: ipaddress.IPv4Address,
        flow: Flow | None = None,
    ) -> ipaddress.IPv4Address:
        """Return the real destination for a mapped destination address.

        Pre-8.3: static rule maps mapped_addr -> real_addr. When ``flow`` is given, a port
        static (``static ... tcp|udp``) only applies to a flow of that protocol and mapped port.
        Returns dst unchanged if no matching static rule exists.
        """
        dst_int = int(dst)
        for rule in self._nat_rules:
            if rule.nat_type != NatType.static:
                continue
            if rule.mapped_interface != ingress_interface:
                continue
            if not rule.mapped_addr.contains(dst_int):
                continue
            port_static_miss = (
                flow is not None
                and rule.proto is not None
                and (flow.proto != rule.proto or not rule.mapped_ports.contains(flow.dst_port))
            )
            if port_static_miss:
                continue
            real_nets = rule.real_addr.to_networks()
            mapped_nets = rule.mapped_addr.to_networks()
            if real_nets and mapped_nets:
                # Offset-preserving translation for subnet statics
                offset = dst_int - int(mapped_nets[0].network_address)
                translated = int(real_nets[0].network_address) + offset
                return ipaddress.IPv4Address(translated)
        return dst
