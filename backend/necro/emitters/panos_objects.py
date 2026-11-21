"""Address objects, address groups and service objects for the PAN-OS emitter.

Objects are content-addressed: the same set of networks or ports always maps to the same object,
and names are derived from the content (hosts reuse the config's ``name`` alias when there is one).
The IR flattens object-groups while parsing, so the source group names are not available here.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Mapping

from necro.emitters.panos_names import NameRegistry
from necro.sets import AddrSet, PortSet

ANY = "any"
_TCP = 6
_UDP = 17
_PROTOCOL_NAMES = {_TCP: "tcp", _UDP: "udp"}
_MAX_SERVICE_LABEL = 40


def port_spec(ports: PortSet) -> str:
    """``80,443,8080-8090``: the PAN-OS port list for a normalized port set."""
    return ",".join(str(iv.lo) if iv.lo == iv.hi else f"{iv.lo}-{iv.hi}" for iv in ports.intervals)


def name_token(text: str) -> str:
    """Quote a name for a ``set`` command when it holds characters outside ``[A-Za-z0-9_.-]``."""
    plain = text != "" and all(c.isascii() and (c.isalnum() or c in "_.-") for c in text)
    return text if plain else '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def name_list(names: list[str]) -> str:
    """``x`` for one name, ``[ x y ]`` for several."""
    tokens = [name_token(n) for n in names]
    return tokens[0] if len(tokens) == 1 else "[ " + " ".join(tokens) + " ]"


class ObjectTable:
    """Collects the address, address-group and service objects the rules refer to."""

    def __init__(self, aliases: Mapping[str, str] | None = None) -> None:
        # ip -> alias label; the alphabetically first label wins when two names share an address
        self._labels: dict[str, str] = {}
        for label, ip in sorted(aliases.items() if aliases else [], reverse=True):
            self._labels[ip] = label
        self._addresses = NameRegistry()
        self._groups = NameRegistry()
        self._services = NameRegistry()
        self._address_defs: dict[str, str] = {}
        self._group_members: dict[str, list[str]] = {}
        self._service_defs: dict[str, str] = {}

    # -- addresses ------------------------------------------------------------------------

    def address(self, addresses: AddrSet) -> str:
        """The object (or group) name that matches ``addresses``, or ``any``."""
        if addresses == AddrSet.any():
            return ANY
        nets = addresses.to_networks()
        if len(nets) == 1:
            return self._network(nets[0])
        key = "group:" + ",".join(str(n) for n in nets)
        if key in self._groups:
            return self._groups.name(key)
        members = [self._network(n) for n in nets]
        name = self._groups.name(key, f"g-{len(nets)}-{str(nets[0]).replace('/', '-')}")
        self._group_members[name] = members
        return name

    def _network(self, net: ipaddress.IPv4Network) -> str:
        key = f"net:{net}"
        if key in self._addresses:
            return self._addresses.name(key)
        if net.prefixlen == 32:
            ip = str(net.network_address)
            preferred = self._labels.get(ip) or f"h-{ip}"
        else:
            preferred = f"n-{str(net).replace('/', '-')}"
        name = self._addresses.name(key, preferred)
        self._address_defs[name] = f"set address {name} ip-netmask {net}"
        return name

    # -- services -------------------------------------------------------------------------

    def service(self, proto: int, sport: PortSet, dport: PortSet) -> str:
        """The TCP/UDP service object for these source and destination ports."""
        label = _PROTOCOL_NAMES[proto]
        sp = "" if sport == PortSet.any() else port_spec(sport)
        dp = port_spec(dport)
        key = f"{label}:{sp}:{dp}"
        if key in self._services:
            return self._services.name(key)
        parts = [label, *([f"sp{sp.replace(',', '_')}"] if sp else []), dp.replace(",", "_")]
        preferred = "-".join(parts)
        if len(preferred) > _MAX_SERVICE_LABEL:
            digest = hashlib.sha1(key.encode("utf-8"), usedforsecurity=False).hexdigest()
            preferred = f"{label}-{digest[:8]}"
        name = self._services.name(key, preferred)
        source = f" source-port {sp}" if sp else ""
        self._service_defs[name] = f"set service {name} protocol {label} port {dp}{source}"
        return name

    # -- output ---------------------------------------------------------------------------

    def address_lines(self) -> list[str]:
        return [self._address_defs[n] for n in sorted(self._address_defs)]

    def group_lines(self) -> list[str]:
        return [
            f"set address-group {n} static {name_list(self._group_members[n])}"
            for n in sorted(self._group_members)
        ]

    def service_lines(self) -> list[str]:
        return [self._service_defs[n] for n in sorted(self._service_defs)]
