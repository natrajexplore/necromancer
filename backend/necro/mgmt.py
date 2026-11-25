"""Management services of a PAN-OS interface-management profile, and the flows they admit.

Policy-semantics 1.3 and 7: traffic addressed to the device itself is not governed by security
rules. It is governed by the management commands of the source (ASA ``telnet``/``ssh``/``http``/
``icmp``/``snmp-server host``, IOS ``vty`` and SNMP lines) and, on PAN-OS, by an interface
management profile: a set of enabled services plus one ``permitted-ip`` list per interface.

The emitter builds profiles from the IR, the PAN-OS reader turns them back into ``MgmtAccess``
entries, and ``evaluate.decide`` answers a flow to the device from those entries. All three share
this table, so a service means the same thing everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from necro.boxes import KIND_ICMP, KIND_TCP, KIND_UDP, Box
from necro.ir import Action, Dialect, Flow, Policy
from necro.sets import AddrSet, PortSet

_ANY_ESTABLISHED = PortSet([(0, 1)])
_ANY_ICMP_TYPE = PortSet([(0, 256)])  # 256 stands for an ICMP flow without a type (boxes.py)


@dataclass(frozen=True)
class MgmtService:
    """One service key of an interface-management profile and the traffic it admits."""

    name: str
    kind: str  # box kind: tcp, udp or icmp
    value: int  # destination port; unused for ping, which stands for ICMP of every type


SERVICES: tuple[MgmtService, ...] = (
    MgmtService("telnet", KIND_TCP, 23),
    MgmtService("ssh", KIND_TCP, 22),
    MgmtService("http", KIND_TCP, 80),
    MgmtService("https", KIND_TCP, 443),
    MgmtService("snmp", KIND_UDP, 161),
    MgmtService("ping", KIND_ICMP, 0),
)
SERVICE_NAMES = tuple(s.name for s in SERVICES)
_BY_NAME = {s.name: s for s in SERVICES}
_PROTO_KIND = {6: KIND_TCP, 17: KIND_UDP, 1: KIND_ICMP}


def service_of_flow(flow: Flow) -> str | None:
    """The management service a flow addressed to the device asks for, or None.

    ``ping`` is the profile key that admits ICMP. The source's ``icmp`` lists and the profile
    both decide per source address, not per ICMP type, so every ICMP type maps to it.
    """
    kind = _PROTO_KIND.get(flow.proto)
    if kind is None:
        return None
    if kind == KIND_ICMP:
        return "ping"
    value = flow.dst_port
    for service in SERVICES:
        if service.kind == kind and service.value == value:
            return service.name
    return None


def service_box(name: str, src: AddrSet, dst: AddrSet) -> Box:
    """The flows that ask for management service ``name`` from ``src`` to ``dst``."""
    service = _BY_NAME[name]
    if service.kind == KIND_ICMP:
        return Box(KIND_ICMP, (src, dst, _ANY_ICMP_TYPE))
    return Box(
        service.kind,
        (src, dst, PortSet.any(), PortSet.single(service.value), _ANY_ESTABLISHED),
    )


def access_services(dialect: Dialect, proto: str) -> list[str]:
    """Profile services a source management command maps to (empty: no PAN-OS equivalent).

    ASA ``http`` serves ASDM over HTTPS. IOS ``ip http server`` is plain HTTP. A bare ``vty``
    line (no ``transport input``) accepts telnet and ssh.
    """
    if proto in ("telnet", "ssh", "snmp"):
        return [proto]
    if proto == "icmp":
        return ["ping"]
    if proto == "http":
        return ["http"] if dialect == Dialect.ios else ["https"]
    if proto == "vty":
        return ["telnet", "ssh"]
    return []


# ---------------------------------------------------------------------------
# PIX/ASA source side (policy-semantics 1.3)
# ---------------------------------------------------------------------------

# profile service -> the management command that admits it on PIX/ASA
_SOURCE_COMMAND = {"telnet": "telnet", "ssh": "ssh", "https": "http", "snmp": "snmp"}


def icmp_sources(policy: Policy, interface: str) -> AddrSet:
    """Sources the ``icmp`` lines let ping the interface: first match wins, then implicit deny.

    An interface with no ``icmp`` line at all admits all ICMP.
    """
    entries = [m for m in policy.mgmt_access if m.proto == "icmp" and m.interface == interface]
    if not entries:
        return AddrSet.any()
    permitted = AddrSet()
    denied = AddrSet()
    for entry in entries:
        if entry.action == Action.permit:
            permitted = permitted.union(entry.src_addr.subtract(denied))
        else:
            denied = denied.union(entry.src_addr)
    return permitted


def source_sources(policy: Policy, interface: str, service: str) -> AddrSet:
    """Sources a PIX/ASA management command admits to ``service`` on ``interface``."""
    if service == "ping":
        return icmp_sources(policy, interface)
    command = _SOURCE_COMMAND.get(service)
    if command is None or (command == "http" and not policy.http_server_enabled):
        return AddrSet()
    admitted = AddrSet()
    for entry in policy.mgmt_access:
        if entry.proto == command and entry.interface == interface:
            admitted = admitted.union(entry.src_addr)
    return admitted


def own_address(policy: Policy, interface: str) -> AddrSet:
    """The interface's own IP as a host set (empty when it has none)."""
    for item in policy.interfaces:
        if item.nameif == interface and item.ip_address is not None:
            return AddrSet.from_host(item.ip_address.ip)
    return AddrSet()


def source_admits(policy: Policy, interface: str, flow: Flow) -> str | None:
    """The service that admits a PIX/ASA flow to the device, or None when it is denied.

    The flow must target the address of the interface it arrives on (no far-interface access)
    and a management command of that interface must admit its source.
    """
    service = service_of_flow(flow)
    if service is None or not own_address(policy, interface).contains(flow.dst):
        return None
    return service if source_sources(policy, interface, service).contains(flow.src) else None


def source_boxes(policy: Policy, interface: str) -> list[Box]:
    """Every flow the PIX/ASA management commands admit on ``interface``, as boxes."""
    host = own_address(policy, interface)
    boxes: list[Box] = []
    if host.is_empty():
        return boxes
    for service in SERVICE_NAMES:
        sources = source_sources(policy, interface, service)
        if not sources.is_empty():
            boxes.append(service_box(service, sources, host))
    return boxes
