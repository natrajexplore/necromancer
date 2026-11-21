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

from necro.ir import Flow, NatType, Policy


class NatModel:
    """Pre-8.3 NAT model for nat-control enforcement."""

    def __init__(self, policy: Policy) -> None:
        self._nat_rules = policy.nat_rules

    def translates(self, ingress_interface: str, flow: Flow) -> bool:
        """Return True if the flow has a matching NAT translation.

        Called by evaluate.py when nat-control is active.

        A flow is considered translated when:
          - A nat0 exemption rule covers the source (no translation needed).
          - A static rule maps the destination address (ingress on mapped_if).
          - A nat/global pair covers the source (ingress on real_if).
        """
        src_int = int(flow.src)
        dst_int = int(flow.dst)

        for rule in self._nat_rules:
            if rule.nat_type == NatType.nat0:
                # nat exemption: source on the real interface
                if rule.real_interface == ingress_interface and rule.real_addr.contains(src_int):
                    return True

            elif rule.nat_type == NatType.static:
                # Inbound static: mapped interface match
                mapped_hit = (
                    rule.mapped_interface == ingress_interface
                    and rule.mapped_addr.contains(dst_int)
                )
                if mapped_hit:
                    return True
                # Outbound static (reverse direction)
                if rule.real_interface == ingress_interface and rule.real_addr.contains(dst_int):
                    return True

            elif (
                rule.nat_type in (NatType.dynamic, NatType.pat)
                and rule.real_interface == ingress_interface
                and rule.real_addr.contains(src_int)
            ):
                # Dynamic NAT/PAT: source on the real interface
                return True

        return False

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
