# Design: necro-engine

## Overview
```
 raw config ─► redact ─► detect ─► Parser(dialect) ─► Policy IR ─┬─► coverage ──► LineRecords
                                                                  ├─► Autopsy ───► Findings
                                                                  ├─► Tighten ───► IR' + Exorcism Ledger
                                                                  └─► PAN-OS Emitter ─► set commands ─► validate_panos (G3)
                                                                                          │
                                                re-parse emitted (panos_reader) ◄─────────┘
                                                                  │
          Oracle: ∀ ctx, flow:  decide(IR, ctx, f) ≡ decide(IR_panos, zone(ctx), to_panos_space(f)) | ledger
                  + golden flows (hand-verified, independent of evaluate.py)
```
The oracle compares against the IR **re-read from the emitted PAN-OS text** (`parsers/panos_reader.py`), not against
the IR it was emitted from. That way emitter bugs get caught, which is what makes the proof meaningful.

## Data model (`necro/ir.py`)
```python
class PortSet(BaseModel):        # normalized, merged inclusive intervals within 0..65535
    ranges: tuple[tuple[int, int], ...]

class AddrSet(BaseModel):        # normalized, merged IPv4 intervals (stored as int ranges; CIDRs derived)
    ranges: tuple[tuple[int, int], ...]

Proto = Literal["ip", "tcp", "udp", "icmp"] | int

class Match(BaseModel):
    protocols: frozenset[int] | None          # None = ip (any); protocol groups expand to several numbers
    src: AddrSet
    dst: AddrSet
    sport: PortSet                             # full range when unused
    dport: PortSet
    icmp_types: frozenset[int] | None = None   # None = all types
    established: bool | None = None            # IOS only; None = don't care

class Rule(BaseModel):
    id: str                  # "<acl>#<seq>", seq = 1-based ACE ordinal as written (remarks excluded)
    acl: str
    seq: int
    vendor_seq: int | None   # IOS named-ACL sequence number, if present
    action: Literal["permit", "deny"]
    match: Match
    source_line: int
    inactive: bool = False
    remark: str | None = None
    log: bool = False
    time_range: str | None = None
    refs: tuple[str, ...] = ()     # object / group names used (for emitter naming and unused-object findings)
    hit_count: int | None = None   # Phase 2

class Interface(BaseModel):
    name: str                       # nameif (ASA/PIX) or interface name (IOS)
    hw: str | None
    zone: str                       # PAN-OS zone name (nameif; IOS: description if unique, else slug(name))
    security_level: int | None      # ASA/PIX only
    addresses: tuple[IPv4Interface, ...]

class Route(BaseModel):
    prefix: IPv4Network
    interface: str
    next_hop: IPv4Address | None
    source: Literal["connected", "static"]

class NatRule(BaseModel):
    kind: Literal["static", "dynamic", "identity", "exempt"]
    real_if: str; mapped_if: str
    real: AddrSet; mapped: AddrSet | None
    style: Literal["pre83", "object", "twice"]
    source_line: int

class Binding(BaseModel):
    acl: str
    interface: str | None          # None for the ASA global ACL
    direction: Literal["in", "out", "global"]

class Context(BaseModel):           # one ingress interface
    name: str                       # "<interface>:in"
    interface: str
    acl: str | None                 # None = implicit behaviour only
    egress_acls: dict[str, str]     # egress interface -> outbound ACL name

class MgmtAccess(BaseModel):        # to-the-box permissions (telnet/ssh/http/snmp/vty access-class)
    service: Literal["telnet", "ssh", "http", "https", "snmp", "icmp"]
    interface: str | None
    src: AddrSet
    source_line: int

class LineRecord(BaseModel):
    line_no: int
    cls: Literal["migrated", "not-policy", "management-plane", "out-of-scope", "unparsed"]
    security_relevant: bool
    reason: str | None

class Policy(BaseModel):
    dialect: Literal["pix", "asa", "ios"]
    os_version: str | None
    mode: Literal["routed", "transparent", "multiple"] = "routed"
    address_space: Literal["mapped", "real", "as-is"]
    interfaces: list[Interface]
    routes: list[Route]
    acls: dict[str, list[Rule]]
    bindings: list[Binding]
    contexts: list[Context]
    nat: list[NatRule]
    nat_control: bool
    same_security_inter: bool
    same_security_intra: bool
    mgmt: list[MgmtAccess]
    objects: dict[str, AddrSet | PortSet | frozenset[int]]
    lines: list[LineRecord]
    unparsed: list[UnparsedLine]
    source_sha256: str

class Flow(BaseModel):
    protocol: int; src: IPv4Address; dst: IPv4Address
    sport: int | None; dport: int | None; icmp_type: int | None; established: bool = False

class Decision(BaseModel):
    action: Literal["permit", "deny"]
    rule_id: str                    # or a reserved implicit id (policy-semantics §0)
    to_zone: str                    # zone name, "self", or "any"
    reason: str | None = None       # e.g. "no-translation", "same-security"
```
Object groups are expanded into sets during parsing. The original object names stay in `objects` and `Rule.refs` so the
emitter can recreate them and autopsy can find unused ones.

## Evaluator (`necro/evaluate.py`)
```
decide(policy, ctx, f):
    to_zone = zones.lookup(policy, f.dst_real)              # longest prefix; "self" for device IPs
    if to_zone == "self": return mgmt_decision(policy, ctx, f)   # ASA: mgmt commands; IOS: ingress ACL applies
    ingress = first_match(policy.acls[ctx.acl]) if ctx.acl
    if dialect in (pix, asa):
        if ingress is None and global_acl: ingress = first_match(global_acl)
        if ingress is None and (ctx.acl or global_acl): return deny("implicit-deny")
        if ingress is None: return security_level_decision(ctx, to_zone)   # implicit-security-level / implicit-deny
        if ingress.deny: return deny(ingress.rule_id)
        if same_level(ctx, to_zone) and not policy.same_security_inter: return deny("same-security-deny")
        if nat_required(policy) and not nat.translates(policy, ctx, to_zone, f): return deny("implicit-deny", "no-translation")
    if dialect == ios:
        if ctx.acl is None: ingress = permit("implicit-permit-no-acl")
        elif ingress is None: return deny("implicit-deny")
        elif ingress.deny: return deny(ingress.rule_id)
    egress = ctx.egress_acls.get(to_zone_interface)
    if egress and not first_match_permits(egress, f): return deny(egress_rule_id)
    return permit(ingress.rule_id, to_zone)
```
- Linear scan, first match. Set membership on normalized interval sets uses `bisect`.
- `match_box(match)` returns a symbolic box (product of interval sets). Autopsy uses `covers(a, b)` and
  `intersects(a, b)`. Shadowing: rule *j* is shadowed iff the union of earlier active rule boxes covers box *j*,
  checked by box subtraction (exact; fine for typical ACLs under 5k rules; capped with a time budget and a
  "not analysed" result instead of a wrong answer).

## Zones (`necro/zones.py`) and NAT (`necro/nat.py`)
- Route table = connected networks + static routes. Longest-prefix match, with a deterministic tie-break (lowest
  administrative distance, then interface name).
- `nat.to_panos_space(policy, ctx, flow)`: for `address_space == "real"` (8.3+), if a static NAT has `mapped_if == ctx.interface`
  and `flow.dst ∈ real`, replace dst with the mapped address. Otherwise identity. `zones.lookup` always uses the real address.

## Oracle (`necro/oracle.py`)
- `flows_for(policy, ctx)` is a Hypothesis strategy built from every rule's boundary points (network, broadcast, ±1, port
  lo-1/lo/hi/hi+1, ICMP types ±1 and all named types), NAT real/mapped addresses and device IPs, mixed with uniform draws.
- `prove(original, emitted_text, ledger, budget, seed) -> ProofResult` runs per context with `hypothesis.find`-style
  search or a wrapped `@given` test. On failure it captures the shrunk example and re-runs `decide` on both sides for the explanation.
- Rule coverage is tracked by recording `rule_id` hits for each side.
- Golden flows are run first. A golden failure short-circuits with that vector as the counterexample.

## Emitter (`necro/emitters/panos.py`)
- Zones: one per interface (`Interface.zone`). Implicit permits are emitted as explicit rules tagged `necro:implicit`, placed
  where the source evaluates them (after the context's ACL rules, before the final deny).
- Rules are split per to-zone (suffix `-z<n>`) when the destination spans several egress interfaces.
- Naming (`panos_names.py`): `slug(original)[:58]`, plus `-<4 hex of sha1>` on collision. The rule name is `<acl>-<seq>[-z<n>]`.
- Services: one `service` object per (protocol, sport, dport) tuple, deduplicated. `neq` becomes a two-range port list.
- ICMP: a custom application per ICMP type set (`necro-icmp-<types>`). IP protocols: a custom application per protocol number
  (`necro-ipproto-<n>`), or the predefined App-ID when it's exact (ledger class `app-id-protocol`).
- Management: `MgmtAccess` → `network profiles interface-management-profile` with `permitted-ip`.
- Output order: zones → address → address-group → service → service-group → application → schedule → profiles → rulebase.
  Deterministic sort inside each section.

## Error handling
- `ParseError(code, message, line_no, path?)` for fatal structure problems (cycles, undefined groups). `UnparsedLine` for skippable ones.
- The API returns a 422 with `{code, message, line_no}`. The UI shows the "unquiet lines" list.

## Testing strategy
- Unit tests per statement type, using fixtures from `samples/dead-configs` and `samples/broken-configs`.
- Golden flows: `tests/test_golden_flows.py` parametrized over every `[[flow]]` in `samples/golden-flows/*.toml`.
- PBT properties P1–P14 (see the `#pbt-playbook` steering doc), marked `@pytest.mark.pbt`.
- **Mutation sanity suite:** every mutant in the playbook MUST make P2 fail with a shrunk counterexample.
- A no-network fixture (socket blocked) wraps the whole suite.
