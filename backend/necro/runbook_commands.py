"""The verification commands of the runbook (migration-governance requirements 5.2 and 5.3).

The commands come from two places and nowhere else:

* every hand-verified golden flow, judged by its hand-verified expectation, and
* for each context, one oracle witness flow for every pair of (source rule, PAN-OS rule) that the
  witnesses reach. The witnesses are what the proof sweeps first, so they are deterministic and
  cover every rule that any flow can reach, whatever the seed.

Each command carries the result it must give. For an oracle flow that is the decision the
equivalence proof compared, so a run on the real devices is a check of that proof. Where the
candidate does not agree with a golden flow, the expected result says so and the proof reports it.

Commands are never invented for an OS that lacks them: ``packet-tracer`` exists from ASA 7.2
(requirement 5.3). For PIX, IOS and older ASA the runbook says so and lists no source commands.
Flows to the device itself and flows with an unresolved egress zone cannot be given to
``test security-policy-match``, so they are listed as manual checks.

Corner witnesses of an ``any`` rule are 0.0.0.0, 255.255.255.255 and port 0, and those of a
subnet rule are its network and broadcast addresses. Nobody should type those into a device, so a
realistic flow with the same decisions is looked for first, with host addresses only.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator, Sequence
from itertools import product
from typing import Literal

from pydantic import BaseModel, Field

from necro.emitters.panos import PanosEmission
from necro.golden import GoldenVector
from necro.ir import Action, Context, Dialect, Flow, Policy
from necro.oracle_core import ProofInputError, Sides, Verdict
from necro.oracle_flows import flow_space
from necro.parsers.panos_reader import tokenize
from necro.rule_text import flow_text

MAX_COMMANDS = 200
PACKET_TRACER_MIN = (7, 2)  # ASA 7.2 added packet-tracer
_VERSION = re.compile(r"^([0-9]+)\.([0-9]+)")
_ICMP_DEFAULT_CODE = 0
_NOT_TESTABLE_ZONES = ("self", "any")
# RFC 5737 documentation addresses, tried when a witness has no usable address
_DEFAULT_SOURCES = ("192.0.2.10", "203.0.113.10")
_DEFAULT_TARGETS = ("198.51.100.10",)
_DEFAULT_SOURCE_PORT = 40000
_DEFAULT_DEST_PORTS = (443, 80, 53, 8080)


class Verification(BaseModel):
    """One command to run, with the result it must give."""

    id: str
    origin: Literal["golden", "oracle"]
    context: str
    command: str
    expected: str
    note: str = ""


class ManualCheck(BaseModel):
    """A flow that no command can verify: it has to be tested another way."""

    id: str
    origin: Literal["golden", "oracle"]
    context: str
    flow: str
    expected: str
    why: str


class Commands(BaseModel):
    """The verification lists. They depend only on the config, the candidate and golden flows."""

    target: list[Verification] = Field(default_factory=list)
    source: list[Verification] = Field(default_factory=list)
    source_note: str = ""
    manual: list[ManualCheck] = Field(default_factory=list)
    omitted: int = 0  # commands left out by the cap


def packet_tracer_supported(policy: Policy) -> bool:
    """``packet-tracer`` exists on ASA 7.2 and later only."""
    match = _VERSION.match(policy.os_version)
    if policy.dialect != Dialect.asa or match is None:
        return False
    return (int(match.group(1)), int(match.group(2))) >= PACKET_TRACER_MIN


def _source_note(policy: Policy) -> str:
    if packet_tracer_supported(policy):
        return ""
    version = policy.os_version or "unknown version"
    return (
        f"packet-tracer is not available on {policy.dialect.value.upper()} {version} (it needs "
        "ASA 7.2 or later), so no source commands are listed. The expected decisions of the "
        "source are evidenced by the equivalence proof and the golden flows."
    )


def _applications(lines: Sequence[str]) -> dict[str, list[str]]:
    """PAN-OS rule name -> its application names, from the emitted ``set`` lines."""
    found: dict[str, list[str]] = {}
    for line_no, line in enumerate(lines, start=1):
        tokens = tokenize(line, line_no)
        if tokens[:4] == ["set", "rulebase", "security", "rules"] and len(tokens) >= 7:
            name, attr, value = tokens[4], tokens[5], tokens[6]
            if attr == "application" and isinstance(name, str):
                found[name] = value if isinstance(value, list) else [str(value)]
    return found


def _rule_name(rule_id: str) -> str:
    """The PAN-OS rule name of a decision's rule id (a rule split by service has ``/n``)."""
    return rule_id.split("/", 1)[0]


def _panos_command(
    from_zone: str, to_zone: str, verdict: Verdict, applications: dict[str, list[str]]
) -> str:
    flow = verdict.panos_flow
    parts = [
        f"test security-policy-match from {from_zone} to {to_zone}",
        f"source {flow.src} destination {flow.dst}",
    ]
    if flow.proto in (6, 17):
        parts.append(f"destination-port {flow.dst_port}")
    parts.append(f"protocol {flow.proto}")
    named = [a for a in applications.get(_rule_name(verdict.resurrected.rule_id), []) if a != "any"]
    if len(named) == 1:
        parts.append(f"application {named[0]}")
    return " ".join(parts)


def _asa_command(nameif: str, flow: Flow) -> str | None:
    head = f"packet-tracer input {nameif}"
    if flow.proto in (6, 17):
        proto = "tcp" if flow.proto == 6 else "udp"
        return f"{head} {proto} {flow.src} {flow.src_port} {flow.dst} {flow.dst_port}"
    if flow.proto == 1:
        if flow.icmp_type is None:
            return None  # a packet always has a type
        return f"{head} icmp {flow.src} {flow.icmp_type} {_ICMP_DEFAULT_CODE} {flow.dst}"
    return f"{head} rawip {flow.src} {flow.proto} {flow.dst}"


def _word(action: Action) -> str:
    return "allow" if action == Action.permit else "deny"


def _expected_target(verdict: Verdict, action: Action) -> str:
    """The result the command must give. When the candidate does not agree with the expected
    action, the text says so: the proof reports that flow as a failure."""
    name = _rule_name(verdict.resurrected.rule_id)
    if verdict.resurrected.action == action:
        text = f"{_word(action)} by rule {name}"
    else:
        text = (
            f"{_word(action)}; the candidate gives {_word(verdict.resurrected.action)} by rule "
            f"{name}, which the proof reports as a failure"
        )
    if verdict.entries:
        text += "; ledger " + ", ".join(e.id for e in verdict.entries)
    return text


def _expected_source(action: Action, rule_id: str) -> str:
    result = "ALLOW" if action == Action.permit else "DROP"
    return f"{result} (source rule {rule_id})"


# -- realistic flows ---------------------------------------------------------------------------


def _usable(address: ipaddress.IPv4Address) -> bool:
    """An address worth typing into a device: not 0.x, multicast, reserved or loopback."""
    return not (
        address.packed[0] == 0
        or address.is_multicast
        or address.is_reserved
        or address.is_loopback
        or address.is_unspecified
    )


def _known_networks(policy: Policy) -> list[ipaddress.IPv4Network]:
    """Every subnet the config mentions: interfaces, routes and the addresses of every rule."""
    found: set[ipaddress.IPv4Network] = set()
    for iface in policy.interfaces:
        if iface.ip_address is not None:
            found.add(iface.ip_address.network)
    found.update(route.network for route in policy.routes)
    for rules in policy.acls.values():
        for rule in rules:
            found.update(rule.match.src.to_networks())
            found.update(rule.match.dst.to_networks())
    return sorted((n for n in found if n.prefixlen <= 30), key=lambda n: (n.prefixlen, n))


class _Subnets:
    """The network and broadcast addresses of the known subnets: not hosts to type in a test."""

    def __init__(self, policy: Policy) -> None:
        self.networks = _known_networks(policy)
        self.special: set[ipaddress.IPv4Address] = set()
        for net in self.networks:
            self.special.update((net.network_address, net.broadcast_address))
        self.owned = {i.ip_address.ip for i in policy.interfaces if i.ip_address is not None}

    def is_host(self, address: ipaddress.IPv4Address) -> bool:
        return _usable(address) and address not in self.special

    def hosts_near(self, address: ipaddress.IPv4Address) -> list[ipaddress.IPv4Address]:
        """Host addresses just inside each subnet that has ``address`` as network or broadcast
        address, nearest first and never an address of the device."""
        found: list[ipaddress.IPv4Address] = []
        for net in reversed(self.networks):  # the most specific subnet first
            if address == net.network_address:
                near = [net.network_address + n for n in range(1, 5)]
            elif address == net.broadcast_address:
                near = [net.broadcast_address - n for n in range(1, 5)]
            else:
                continue
            for host in near:
                fits = host in net and self.is_host(host) and host not in self.owned
                if fits and host not in found:
                    found.append(host)
        return found


def _realistic(flow: Flow, subnets: _Subnets) -> bool:
    if not (subnets.is_host(flow.src) and subnets.is_host(flow.dst)):
        return False
    return flow.proto not in (6, 17) or (flow.src_port > 0 and flow.dst_port > 0)


def _interface_hosts(policy: Policy) -> list[ipaddress.IPv4Address]:
    """One host address in each interface network that is not an address of the device."""
    owned = {i.ip_address.ip for i in policy.interfaces if i.ip_address is not None}
    found: list[ipaddress.IPv4Address] = []
    for iface in policy.interfaces:
        if iface.ip_address is not None:
            host = next((h for h in iface.ip_address.network.hosts() if h not in owned), None)
            if host is not None:
                found.append(host)
    return found


def _variants(flow: Flow, hosts: list[ipaddress.IPv4Address], subnets: _Subnets) -> Iterator[Flow]:
    """The flow with its unusable fields replaced by usable ones, in a fixed order."""
    ported = flow.proto in (6, 17)
    sources = [flow.src]
    if not _usable(flow.src):
        sources = [ipaddress.IPv4Address(a) for a in _DEFAULT_SOURCES]
    elif not subnets.is_host(flow.src):
        sources = subnets.hosts_near(flow.src)
    targets = [flow.dst]
    if not _usable(flow.dst):
        targets = [*hosts, *(ipaddress.IPv4Address(a) for a in _DEFAULT_TARGETS)]
    elif not subnets.is_host(flow.dst):
        targets = subnets.hosts_near(flow.dst)
    source_ports = [_DEFAULT_SOURCE_PORT] if ported and flow.src_port == 0 else [flow.src_port]
    dest_ports = list(_DEFAULT_DEST_PORTS) if ported and flow.dst_port == 0 else [flow.dst_port]
    for src, dst, sport, dport in product(sources, targets, source_ports, dest_ports):
        yield flow.model_copy(update={"src": src, "dst": dst, "src_port": sport, "dst_port": dport})


class _Builder:
    """Collects commands in order, golden flows first, and applies the cap."""

    def __init__(self, policy: Policy, emission: PanosEmission) -> None:
        self.policy = policy
        self.sides = Sides(policy, emission.text, emission.ledger)
        self.applications = _applications(emission.lines)
        self.hosts = _interface_hosts(policy)
        self.subnets = _Subnets(policy)
        self.asa = packet_tracer_supported(policy)
        self.commands = Commands(source_note=_source_note(policy))
        self.seen: set[str] = set()
        self.oracle_count = 0

    def _ident(self, origin: Literal["golden", "oracle"], ident: str) -> str:
        if origin == "golden":
            return ident
        self.oracle_count += 1
        return f"ORC-{self.oracle_count:04d}"

    def _manual(
        self,
        origin: Literal["golden", "oracle"],
        ident: str,
        ctx: Context,
        verdict: Verdict,
        action: Action,
        to_zone: str,
    ) -> None:
        why = (
            "traffic to the device itself follows the interface management profile"
            if to_zone == "self"
            else "the egress zone is not resolved offline (dynamic routing)"
        )
        self.commands.manual.append(
            ManualCheck(
                id=self._ident(origin, ident),
                origin=origin,
                context=ctx.name,
                flow=flow_text(verdict.flow),
                expected=_expected_target(verdict, action),
                why=why,
            )
        )

    def add(
        self,
        origin: Literal["golden", "oracle"],
        ident: str,
        ctx: Context,
        flow: Flow,
        vector: GoldenVector | None = None,
    ) -> None:
        """Add one flow. A golden flow is judged by its hand-verified expectation, an oracle flow
        by the decision the proof compared. An oracle flow that repeats a command is skipped."""
        verdict = self.sides.check(ctx, flow, vector.panos_dst if vector else None)
        if vector is None:
            action = verdict.expected_action
            source_action, source_rule = verdict.original.action, verdict.original.rule_id
            to_zone = verdict.original_zone
        else:
            action = verdict.expected_action if verdict.entries else vector.expect_action
            source_action, source_rule = vector.expect_action, vector.expect_rule
            to_zone = self.sides.zone_name(vector.expect_to_zone)
        if to_zone in _NOT_TESTABLE_ZONES:
            self._manual(origin, ident, ctx, verdict, action, to_zone)
            return
        from_zone = self.sides.zones.of_context(self.policy, ctx)
        command = _panos_command(from_zone, to_zone, verdict, self.applications)
        if origin == "oracle" and command in self.seen:
            return
        self.seen.add(command)
        if len(self.commands.target) >= MAX_COMMANDS:
            self.commands.omitted += 1
            return
        ident = self._ident(origin, ident)
        note = (
            f"ICMP type {flow.icmp_type}" if flow.proto == 1 and flow.icmp_type is not None else ""
        )
        self.commands.target.append(
            Verification(
                id=ident,
                origin=origin,
                context=ctx.name,
                command=command,
                expected=_expected_target(verdict, action),
                note=note,
            )
        )
        source = _asa_command(ctx.interface, verdict.flow) if self.asa else None
        if source is not None:
            self.commands.source.append(
                Verification(
                    id=ident,
                    origin=origin,
                    context=ctx.name,
                    command=source,
                    expected=_expected_source(source_action, source_rule),
                )
            )

    def representative(self, ctx: Context, pair: tuple[str, str], flows: list[Flow]) -> Flow:
        """A realistic flow with the same pair of rule decisions, or the first witness."""
        for flow in flows:
            if _realistic(flow, self.subnets):
                return flow
        for flow in flows:
            before = self.sides.check(ctx, flow)
            for variant in _variants(flow, self.hosts, self.subnets):
                decided = self.sides.check(ctx, variant)
                same = (decided.original.rule_id, decided.resurrected.rule_id) == pair
                if same and decided.original_zone == before.original_zone:
                    return variant
        return flows[0]


def build_commands(
    policy: Policy, emission: PanosEmission, golden: Sequence[GoldenVector] = ()
) -> Commands:
    """The verification command lists for a candidate (requirements 5.2 and 5.3)."""
    builder = _Builder(policy, emission)
    for vector in golden:
        try:
            ctx = builder.sides.context(vector.context)
        except ProofInputError:
            builder.commands.manual.append(
                ManualCheck(
                    id=vector.id,
                    origin="golden",
                    context=vector.context,
                    flow=flow_text(vector.flow),
                    expected=f"{vector.expect_action.value} by {vector.expect_rule}",
                    why="the context does not exist in this config",
                )
            )
            continue
        builder.add("golden", vector.id, ctx, vector.flow, vector)
    for ctx in builder.sides.contexts:
        groups: dict[tuple[str, str], list[Flow]] = {}
        for flow in flow_space(policy, ctx).witnesses:
            decided = builder.sides.check(ctx, flow)
            pair = (decided.original.rule_id, decided.resurrected.rule_id)
            groups.setdefault(pair, []).append(flow)
        for pair, flows in groups.items():
            builder.add("oracle", "", ctx, builder.representative(ctx, pair, flows))
    return builder.commands
