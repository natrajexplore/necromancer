"""Synthetic ASA configs of a given size, for the performance checks (requirement 8.1).

Two shapes, both seeded and deterministic:

* ``realistic``: what a large firewall's ACL looks like. Mostly specific hosts and /24 networks
  with one service, a few ``any`` sources, some ICMP and IP rules, and a few percent of rules
  that are deliberately shadowed or redundant, so autopsy has findings to confirm.
* ``dense``: a stress shape in which rules overlap heavily (/20 networks over a small address
  range, ``any`` on either side of many rules). Autopsy has to cope with it, not only with the
  easy case.

Only RFC 1918 and RFC 5737 addresses.
"""

from __future__ import annotations

import random

_HEADER = """ASA Version 8.2(5)
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 192.0.2.1 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.0.0
interface Ethernet0/2
 nameif dmz
 security-level 50
 ip address 10.2.0.1 255.255.0.0
"""
_FOOTER = """access-group OUTSIDE_IN in interface outside
route outside 0.0.0.0 0.0.0.0 192.0.2.254 1
telnet 10.1.0.0 255.255.0.0 inside
"""
_PORTS = (21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 389, 443, 445, 993, 1433, 3306, 3389, 8080)
_ACL = "access-list OUTSIDE_IN extended"


def _host(rnd: random.Random, blocks: int) -> str:
    return f"10.{rnd.randrange(1, blocks + 1)}.{rnd.randrange(256)}.{rnd.randrange(1, 255)}"


def _net24(rnd: random.Random, blocks: int) -> str:
    return f"10.{rnd.randrange(1, blocks + 1)}.{rnd.randrange(256)}.0 255.255.255.0"


def _net20(rnd: random.Random, blocks: int) -> str:
    return f"10.{rnd.randrange(1, blocks + 1)}.{rnd.randrange(0, 256, 16)}.0 255.255.240.0"


def _realistic_rules(rnd: random.Random, earlier: list[str]) -> list[str]:
    """The next rule, or a pair: a broad rule followed by the narrower one it shadows."""
    kind = rnd.random()
    action = "deny" if rnd.random() < 0.08 else "permit"
    if kind < 0.03 and earlier:  # a copy of an earlier rule: redundant
        return [rnd.choice(earlier)]
    if kind < 0.05:  # a rule for one host and port, then the same for one source: shadowed
        host, port = _host(rnd, 59), rnd.choice(_PORTS)
        return [
            f"{_ACL} permit tcp any host {host} eq {port}",
            f"{_ACL} permit tcp host {_host(rnd, 59)} host {host} eq {port}",
        ]
    if kind < 0.10:
        return [f"{_ACL} permit icmp any host {_host(rnd, 59)} echo-reply"]
    if kind < 0.14:
        return [f"{_ACL} {action} ip host {_host(rnd, 59)} host {_host(rnd, 59)}"]
    if kind < 0.35:
        src = "any" if rnd.random() < 0.15 else f"host {_host(rnd, 59)}"
        low = rnd.randrange(1000, 1100)
        high = rnd.randrange(1100, 1200)
        return [f"{_ACL} {action} tcp {src} {_net24(rnd, 59)} range {low} {high}"]
    proto = rnd.choice(("tcp", "tcp", "tcp", "udp"))
    src = "any" if rnd.random() < 0.12 else f"host {_host(rnd, 59)}"
    port = rnd.choice(_PORTS)
    return [f"{_ACL} {action} {proto} {src} host {_host(rnd, 59)} eq {port}"]


def _dense_rule(rnd: random.Random) -> str:
    action = rnd.choice(("permit", "permit", "deny"))
    proto = rnd.choice(("tcp", "udp", "ip", "icmp"))

    def address() -> str:
        kind = rnd.random()
        if kind < 0.15:
            return "any"
        if kind < 0.6:
            return f"host {_host(rnd, 20)}"
        return _net20(rnd, 20)

    tail = ""
    if proto in ("tcp", "udp"):
        low, high = rnd.randrange(1000, 2000), rnd.randrange(2000, 3000)
        tail = rnd.choice((f" eq {rnd.choice(_PORTS)}", f" range {low} {high}", ""))
    elif proto == "icmp":
        tail = rnd.choice((" echo", " echo-reply", ""))
    return f"{_ACL} {action} {proto} {address()} {address()}{tail}"


def synthetic_config(rules: int, *, shape: str = "realistic", seed: int = 20260101) -> str:
    """An ASA config whose one big ACL has ``rules`` rules, the last of them ``deny ip any any``."""
    if shape not in ("realistic", "dense"):
        raise ValueError(f"unknown shape {shape!r}")
    rnd = random.Random(seed)
    lines: list[str] = []
    while len(lines) < rules - 1:
        if shape == "realistic":
            lines += _realistic_rules(rnd, lines)
        else:
            lines.append(_dense_rule(rnd))
    del lines[rules - 1 :]
    lines.append(f"{_ACL} deny ip any any log")
    return _HEADER + "\n".join(lines) + "\n" + _FOOTER
