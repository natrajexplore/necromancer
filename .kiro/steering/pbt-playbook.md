---
inclusion: manual
---

# Property-based testing playbook (reference with #pbt-playbook)

Properties to implement with Hypothesis. Each one maps to requirements in `.kiro/specs/necro-engine/requirements.md`.

| ID | Property | Kind |
|---|---|---|
| P1 | `parse(render(ir)) == ir` for generated IR (round-trip, per parser dialect) | Round-trip |
| P2 | For every generated flow, `decide(original) == decide(panos_reader(emit(original)))` (action **and** to_zone, after address-space mapping) except for ledger entries | **Oracle / equivalence** |
| P3 | Removing a rule the autopsy flags as *shadowed* or *redundant* changes no decision | Metamorphic |
| P4 | Reordering two adjacent rules with disjoint match sets changes no decision | Metamorphic |
| P5 | Expanding nested object-groups is idempotent: `expand(expand(g)) == expand(g)` | Idempotence |
| P6 | Tightening is monotone: any flow allowed after tightening was allowed before | Invariant |
| P7 | Subnet-mask ↔ wildcard conversion is a bijection on contiguous masks; non-contiguous masks are rejected | Round-trip |
| P8 | The evaluator never raises on any well-formed flow (total function) | Robustness |
| P9 | Set algebra laws on `PortSet`/`AddrSet`: A∪A=A, A∖A=∅, (A∖B)∩B=∅, contains(x) ⇔ A∩{x}≠∅, normalization is canonical | Algebra |
| P10 | Redaction: no secret token from a generated config appears in IR, findings, report, logs or API responses | Invariant |
| P11 | Determinism: the same input, options and seed produce byte-identical emitted config and report body | Invariant |
| P12 | Emitted PAN-OS names are valid, ≤ 63 chars and unique for any generated set of source names (incl. collisions after slugging) | Invariant |
| P13 | NAT mapping: for 8.3+ static NAT, `to_panos_space(real) == mapped` on the mapped ingress and is identity elsewhere | Round-trip |
| P14 | Line accounting: every input line is classified exactly once; `sum(classes) == line_count` | Invariant |

Golden flows (`samples/golden-flows/*.toml`) are **example-based** and complement the properties. They must pass at 100%.

## Strategies
- **Flows:** `src`/`dst` drawn 70% from "interesting" addresses (rule boundaries: network, broadcast, ±1; NAT mapped
  and real addresses; device interface IPs) and 30% uniformly at random. Ports drawn from rule boundaries
  (`lo-1, lo, hi, hi+1`) and well-known ports. Protocol is tcp/udp/icmp/other numbered (incl. 47, 50, 88, 89). ICMP type drawn from
  rule types ±1 and from the full named-type table (so a widened echo-reply → `ping` is caught by type 8). The TCP `established` flag is on or off (IOS).
- **Contexts:** every bound context plus every interface without an ACL (implicit behaviour must be proven too).
- Use `@settings(max_examples=...)` profiles: `dev` = 500, `ci` = 5,000, `demo` = 10,000.
- Use `hypothesis.target()` to steer generation toward rule boundaries.
- Always report the **shrunk** counterexample in user-facing output, with both decisions, both rule ids and both to-zones.

## Mutation sanity suite (the oracle must catch every one)
Each mutant is a deliberately broken emitter or reader. P2 must fail with a shrunk counterexample:
`lt`↔`gt` swap · `range` upper bound off-by-one · `neq` emitted as `eq` · subnet mask emitted as wildcard ·
rule order reversed for two overlapping rules · final deny dropped · inactive rule emitted as enabled ·
ICMP echo-reply widened to the `ping` App-ID · 8.3+ real destination left untranslated · to-zone forced to `any`.
