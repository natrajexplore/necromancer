"""Repository integrity checks for the NECROMANCER scaffold.

Repo tooling, not application code: it validates the Kiro specs, hooks, agents and the synthetic
samples so they stay consistent before (and while) Kiro generates the application.

Run: python -I .github/scripts/check_repo.py   (Python 3.11+, standard library only)
Exit code 0 = all checks pass, 1 = at least one failure.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)


def rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


# 1. .kiro JSON files parse ------------------------------------------------------------------
def check_kiro_json() -> None:
    files = sorted((ROOT / ".kiro").rglob("*.json"))
    if not files:
        fail(".kiro: no JSON files found")
    for f in files:
        try:
            json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            fail(f"{rel(f)}: invalid JSON ({e})")


# 2. .kiro is never git-ignored (hackathon rule) ---------------------------------------------
def check_kiro_not_ignored() -> None:
    probes = [".kiro", ".kiro/specs/necro-engine/tasks.md", ".kiro/steering/tech.md", ".kiro/hooks/proof-of-life.json"]
    try:
        r = subprocess.run(["git", "check-ignore", *probes], cwd=ROOT, capture_output=True, text=True)
    except FileNotFoundError:
        return  # git not available; skip
    if r.stdout.strip():
        fail(f".kiro paths are git-ignored (disqualification risk): {r.stdout.split()}")


# 3. Spec traceability: every acceptance criterion has a task, every task reference exists ---
REQ_LINE = re.compile(r"^(\d+\.\d+)\s", re.M)
TASK_REF = re.compile(r"_Requirements:\s*([^_]+)_")


def check_traceability() -> None:
    for spec in sorted((ROOT / ".kiro" / "specs").iterdir()):
        req_f, tasks_f = spec / "requirements.md", spec / "tasks.md"
        if not (req_f.exists() and tasks_f.exists()):
            fail(f"{rel(spec)}: missing requirements.md or tasks.md")
            continue
        reqs = set(REQ_LINE.findall(req_f.read_text(encoding="utf-8")))
        refs: set[str] = set()
        for m in TASK_REF.finditer(tasks_f.read_text(encoding="utf-8")):
            refs.update(x.strip() for x in m.group(1).split(",") if x.strip())
        for r in sorted(reqs - refs):
            fail(f"{rel(spec)}: requirement {r} is not referenced by any task")
        for r in sorted(refs - reqs):
            fail(f"{rel(spec)}: tasks reference unknown requirement {r}")


# 4. Sample annotations sit directly above a config line -------------------------------------
MARKER = re.compile(r"^! (GHOST|UNSUPPORTED|EXPECT-UNPARSED):\s*\S")


def check_markers() -> None:
    for f in sorted((ROOT / "samples").rglob("*.cfg")):
        lines = f.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if MARKER.match(line):
                nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
                if not nxt or nxt.startswith("!"):
                    fail(f"{rel(f)}:{i + 1}: annotation is not directly above a config line")


# 5. Samples use synthetic addresses only (RFC 5737 / RFC 1918 / RFC 3849) -------------------
ALLOWED_V4 = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",       # RFC 5737 documentation
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",          # RFC 1918 private
    "0.0.0.0/8",                                              # "this network": masks/wildcards, never a host
    "255.255.255.255/32",
)]
ALLOWED_V6 = ipaddress.ip_network("2001:db8::/32")
V4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def is_mask(a: ipaddress.IPv4Address) -> bool:
    n = int(a)
    inv = n ^ 0xFFFFFFFF
    return (inv & (inv + 1)) == 0 or (n & (n + 1)) == 0  # subnet mask or contiguous wildcard


def check_synthetic_ips() -> None:
    for f in sorted((ROOT / "samples").rglob("*")):
        if f.suffix not in {".cfg", ".toml", ".md"}:
            continue
        for no, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            for tok in V4.findall(line):
                try:
                    a = ipaddress.IPv4Address(tok)
                except ipaddress.AddressValueError:
                    continue
                if not (any(a in n for n in ALLOWED_V4) or is_mask(a)):
                    fail(f"{rel(f)}:{no}: non-synthetic IPv4 address {tok}")
            for tok in re.findall(r"[0-9A-Fa-f:]*::[0-9A-Fa-f:]*", line):
                try:
                    a6 = ipaddress.IPv6Address(tok)
                except ipaddress.AddressValueError:
                    continue
                if a6 not in ALLOWED_V6 and a6 != ipaddress.IPv6Address("::"):
                    fail(f"{rel(f)}:{no}: non-synthetic IPv6 address {tok}")


# 6. Golden flows are well-formed and point at real configs ----------------------------------
REQUIRED = ("id", "note", "context", "protocol", "src", "dst", "expect_action", "expect_rule")
PSEUDO_RULES = {"implicit-deny", "implicit-permit-no-acl", "implicit-security-level"}


def check_golden_flows() -> None:
    gdir = ROOT / "samples" / "golden-flows"
    files = sorted(gdir.glob("*.toml"))
    if not files:
        fail("samples/golden-flows: no TOML files")
    seen: set[str] = set()
    total = 0
    for f in files:
        try:
            d = tomllib.loads(f.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as e:
            fail(f"{rel(f)}: invalid TOML ({e})")
            continue
        cfg = ROOT / "samples" / d.get("config", "")
        if not d.get("config") or not cfg.is_file():
            fail(f"{rel(f)}: 'config' missing or not found: {d.get('config')}")
            continue
        cfg_text = cfg.read_text(encoding="utf-8")
        for fl in d.get("flow", []):
            total += 1
            fid = fl.get("id", "?")
            where = f"{rel(f)} [{fid}]"
            for k in REQUIRED:
                if k not in fl:
                    fail(f"{where}: missing field '{k}'")
            if fid in seen:
                fail(f"{where}: duplicate flow id")
            seen.add(fid)
            if fl.get("expect_action") not in ("permit", "deny"):
                fail(f"{where}: expect_action must be permit|deny")
            proto = fl.get("protocol")
            if not (proto in ("tcp", "udp", "icmp", "ip") or (isinstance(proto, int) and 0 <= proto <= 255)):
                fail(f"{where}: bad protocol {proto!r}")
            for k in ("src", "dst", "expect_panos_dst"):
                if k in fl:
                    try:
                        ipaddress.ip_address(fl[k])
                    except ValueError:
                        fail(f"{where}: {k} is not an IP address")
            for k in ("sport", "dport"):
                if k in fl and not (isinstance(fl[k], int) and 0 <= fl[k] <= 65535):
                    fail(f"{where}: {k} out of range")
            if proto in ("tcp", "udp") and "dport" not in fl:
                fail(f"{where}: tcp/udp flow without dport")
            iface = str(fl.get("context", "")).rsplit(":", 1)[0]
            if iface and iface not in cfg_text:
                fail(f"{where}: context interface '{iface}' not found in {d['config']}")
            rule = str(fl.get("expect_rule", ""))
            if "#" in rule:
                acl = rule.split("#", 1)[0]
                if not re.search(rf"access-list\s+(?:extended\s+|standard\s+)?{re.escape(acl)}\b", cfg_text):
                    fail(f"{where}: ACL '{acl}' not found in {d['config']}")
            elif rule not in PSEUDO_RULES:
                fail(f"{where}: unknown expect_rule '{rule}'")
    print(f"golden flows: {total} flows in {len(files)} files")


def main() -> int:
    for check in (check_kiro_json, check_kiro_not_ignored, check_traceability, check_markers,
                  check_synthetic_ips, check_golden_flows):
        before = len(errors)
        check()
        status = "ok" if len(errors) == before else f"{len(errors) - before} error(s)"
        print(f"{check.__name__}: {status}")
    for e in errors:
        print(f"::error::{e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
