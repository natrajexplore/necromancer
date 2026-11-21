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
from necro.ir import Dialect, Flow
from necro.sets import AddrSet, PortSet

_ANY_ESTABLISHED = PortSet([(0, 1)])


@dataclass(frozen=True)
class MgmtService:
    """One service key of an interface-management profile and the traffic it admits."""

    name: str
    kind: str  # box kind: tcp, udp or icmp
    value: int  # destination port, or the ICMP type for ping


SERVICES: tuple[MgmtService, ...] = (
    MgmtService("telnet", KIND_TCP, 23),
    MgmtService("ssh", KIND_TCP, 22),
    MgmtService("http", KIND_TCP, 80),
    MgmtService("https", KIND_TCP, 443),
    MgmtService("snmp", KIND_UDP, 161),
    MgmtService("ping", KIND_ICMP, 8),
)
SERVICE_NAMES = tuple(s.name for s in SERVICES)
_BY_NAME = {s.name: s for s in SERVICES}
_PROTO_KIND = {6: KIND_TCP, 17: KIND_UDP, 1: KIND_ICMP}


def service_of_flow(flow: Flow) -> str | None:
    """The management service a flow addressed to the device asks for, or None."""
    kind = _PROTO_KIND.get(flow.proto)
    if kind is None:
        return None
    value = flow.icmp_type if kind == KIND_ICMP else flow.dst_port
    for service in SERVICES:
        if service.kind == kind and service.value == value:
            return service.name
    return None


def service_box(name: str, src: AddrSet, dst: AddrSet) -> Box:
    """The flows that ask for management service ``name`` from ``src`` to ``dst``."""
    service = _BY_NAME[name]
    if service.kind == KIND_ICMP:
        return Box(KIND_ICMP, (src, dst, PortSet.single(service.value)))
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
