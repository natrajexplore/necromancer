"""PAN-OS NAT rules for static NAT in pre-8.3 sources (requirement 4.11).

An inbound static (``static (inside,outside) <mapped> <real>``) is a destination NAT on PAN-OS: a
security rule matches the pre-NAT (mapped) destination, and the zone it names is the post-NAT zone.
The emitted NAT rule is what lets PAN-OS, and ``panos_reader``, find that zone from the real
address. Identity statics change nothing and need no rule.

Only single-host statics are emitted. Subnet statics, port statics and ASA 8.3+ object NAT are not
expressed here, so they are reported as unsupported and block the verdict. Dynamic NAT and PAT
change source addresses only, which no security decision depends on (policy-semantics 1.5); they
are listed in the emission notes, not emitted.
"""

from __future__ import annotations

from necro.emitters.panos_env import ANY_ZONE, BuildEnv
from necro.emitters.panos_names import NameRegistry
from necro.emitters.panos_objects import ObjectTable
from necro.ir import AddressSpace, NatRule, NatType
from necro.sets import AddrSet

_SOURCE_NAT_NOTE = (
    "Dynamic NAT, PAT and nat 0 lines are not emitted (Phase 2, requirement 4.12). They "
    "translate source addresses only, so no security decision changes; add source NAT "
    "on the PAN-OS before cutover."
)


def _text(addresses: AddrSet) -> str:
    nets = addresses.to_networks()
    return ", ".join(str(n) for n in nets) if nets else "no address"


def _label(rule: NatRule) -> str:
    return f"{_text(rule.mapped_addr)} (mapped) -> {_text(rule.real_addr)} (real)"


def nat_lines(env: BuildEnv, objects: ObjectTable) -> list[str]:
    """``set`` commands for the static destination NAT rules the security rules rely on."""
    policy = env.policy
    statics = [r for r in policy.nat_rules if r.nat_type == NatType.static]
    if any(r.nat_type != NatType.static for r in policy.nat_rules):
        env.notes.append(_SOURCE_NAT_NOTE)
    if policy.address_space == AddressSpace.real:
        if any(r.real_addr != r.mapped_addr for r in statics):
            env.unsupported.append(
                "Static NAT with different real and mapped addresses on an ASA 8.3+ source: its "
                "ACLs name real addresses, which PAN-OS rules must replace with the mapped "
                "address for flows arriving on the mapped interface (Phase 2, requirement 4.12)"
            )
        return []
    names = NameRegistry()
    lines: list[str] = []
    for rule in statics:
        if rule.real_addr == rule.mapped_addr:
            continue  # identity static: the pre-NAT and post-NAT address are the same
        real_nets, mapped_nets = rule.real_addr.to_networks(), rule.mapped_addr.to_networks()
        if rule.proto is not None:
            env.unsupported.append(f"Static NAT with port translation: {_label(rule)}")
        elif not (
            len(real_nets) == 1
            and len(mapped_nets) == 1
            and real_nets[0].prefixlen == mapped_nets[0].prefixlen == 32
        ):
            env.unsupported.append(f"Static NAT of a subnet or range: {_label(rule)}")
        elif rule.mapped_interface not in env.zones.by_nameif:
            env.unsupported.append(f"Static NAT on an unknown interface: {_label(rule)}")
        else:
            lines += _host_rule(env, objects, names, rule)
    return lines


def _host_rule(
    env: BuildEnv, objects: ObjectTable, names: NameRegistry, rule: NatRule
) -> list[str]:
    parts = env.routes.partition(rule.mapped_addr)
    to_zone = env.zones.of_nameif(parts[0][0] if parts else ANY_ZONE)
    mapped = str(rule.mapped_addr.to_networks()[0].network_address)
    real = str(rule.real_addr.to_networks()[0].network_address)
    name = names.name(f"{rule.mapped_interface}|{mapped}|{real}", f"necro-nat-{mapped}")
    head = f"set rulebase nat rules {name}"
    return [
        f"{head} from {env.zones.by_nameif[rule.mapped_interface]}",
        f"{head} to {to_zone}",
        f"{head} source any",
        f"{head} destination {objects.address(rule.mapped_addr)}",
        f"{head} service any",
        f"{head} destination-translation translated-address {real}",
    ]
