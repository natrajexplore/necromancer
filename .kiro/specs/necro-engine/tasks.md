# Implementation Plan: necro-engine

## Phase 1: hackathon MVP (due 2026-11-30)

- [ ] 1. Project skeleton
  - Create `backend/` with `uv`, `.python-version` (3.12), `pyproject.toml` (fastapi, pydantic, hypothesis, pytest, pytest-cov, ruff, mypy, mangum, mcp, pip-audit)
  - `tests/conftest.py`: pytest marker `pbt`, Hypothesis profiles dev/ci/demo selected by `HYPOTHESIS_PROFILE` (default dev), socket-blocking fixture
  - Commit `uv.lock`; confirm the existing `.github/workflows/ci.yml` backend job activates and passes (adjust only if a command differs from tech steering)
  - _Requirements: 6.2, 8.2, 8.3, 8.4_

- [ ] 2. IR and normalized sets
- [ ] 2.1 `sets.py`: `PortSet` and `AddrSet` with normalization (sort, merge, clamp) plus `contains`, `intersect`, `subtract`, `covers`; PBT P9
  - _Requirements: 2.2_
- [ ] 2.2 `ir.py`: `Match`, `Rule`, `Interface`, `Route`, `NatRule`, `Binding`, `Context`, `MgmtAccess`, `LineRecord`, `Policy`, `Flow`, `Decision`
  - _Requirements: 2.1_
- [ ] 2.3 `masks.py`: subnet ↔ wildcard conversion, rejecting non-contiguous masks; PBT P7
  - _Requirements: 1.1, 1.2, 1.12_
- [ ] 2.4 `names.py`: (protocol, name) tables from policy-semantics §4, with unit tests for the 514/512/radius traps
  - _Requirements: 1.10_
- [ ] 2.5 `redact.py`: every pattern in security steering; PBT P10 over generated configs
  - _Requirements: 1.6_

- [ ] 3. Evaluator, zones, NAT model
- [ ] 3.1 `zones.py`: route table + longest-prefix match + `self`
  - _Requirements: 2.5_
- [ ] 3.2 `evaluate.py`: `decide()` with first-match, implicit deny, inactive-skip, security levels, same-security, nat-control, IOS no-ACL permit, outbound ACLs; PBT P8
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 1.7_
- [ ] 3.3 `nat.py`: pre-8.3 `static`/`nat`/`global` model + `translates()` for nat-control
  - _Requirements: 2.4, 4.11_

- [ ] 4. Parsers
- [ ] 4.1 `pix_asa.py`: names, interfaces/nameif/security-level, routes, object-groups (+ nested, cycle and undefined detection), extended ACLs (remark/log/inactive/time-range), access-group in/out, same-security-traffic, nat-control, static/nat/global, telnet/ssh/http mgmt
  - Fixtures: `pix-2006-hq.cfg`, `asa-8.2-branch.cfg`, `broken-configs/asa-*.cfg`
  - _Requirements: 1.1, 1.4, 1.5, 1.7, 1.12_
- [ ] 4.2 `ios_acl.py`: standard + extended (numbered, named, sequence numbers, remark, established), interface bindings in/out, ip route, ACL classification by reference, vty access-class
  - Fixtures: `ios-12-edge.cfg`, `broken-configs/ios-unsupported-constructs.cfg` (every `EXPECT-UNPARSED` reason matches)
  - _Requirements: 1.2, 1.11, 1.12_
- [ ] 4.3 `detect.py`: dialect, OS version and mode with confidence
  - _Requirements: 1.3_
- [ ] 4.4 `coverage.py`: classify every line; PBT P14
  - _Requirements: 1.9_
- [ ] 4.5 Renderer per dialect (IR → text) and PBT P1 round-trip
  - _Requirements: 1.8_
- [ ] 4.6 `tests/test_golden_flows.py` for PIX, ASA 8.2 and IOS vectors (original side)
  - _Requirements: 2.7_

- [ ] 5. Autopsy
- [ ] 5.1 Shadowed and redundant detection using box coverage; PBT P3
  - _Requirements: 3.1, 3.2, 3.7_
- [ ] 5.2 Overly broad, insecure service, unused object/ACL, insecure management, unfiltered interface, return-traffic, no-remark findings with severity (zone trust), explanation and recommendation
  - Test: seeded-ghost recall = 100% on every sample (`test_autopsy_recall.py`)
  - _Requirements: 3.3, 3.4, 3.5, 3.6, 3.8, 3.9, 3.10, 3.13, 3.14_

- [ ] 6. PAN-OS emitter + reader
- [ ] 6.1 Zones, objects, groups, services (neq → two ranges), rules in order, implicit-permit rules, explicit final deny; `panos_names.py`; PBT P12
  - _Requirements: 4.1, 4.2, 4.4, 4.6, 4.8_
- [ ] 6.2 To-zone per rule with splitting
  - _Requirements: 4.5_
- [ ] 6.3 ICMP-type and IP-protocol custom applications; lossy-mapping ledger entries; established omission; mgmt profiles
  - _Requirements: 4.3, 4.7, 4.9, 4.10_
- [ ] 6.4 Pre-8.3 address-space handling
  - _Requirements: 4.11_
- [ ] 6.5 `panos_reader.py`: parse emitted `set` commands back into IR (used by the oracle)
  - _Requirements: 6.1_
- [ ] 6.6 Determinism test; PBT P11
  - _Requirements: 4.14_

- [ ] 7. Tightening + exorcism ledger
  - Remediations from findings, ledger entries with approval state, separate baseline/tightened artifacts; PBT P6
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 8. Proof of Life oracle
- [ ] 8.1 Boundary-biased flow strategy (incl. NAT and device addresses, all named ICMP types) with `hypothesis.target()`
  - _Requirements: 6.1_
- [ ] 8.2 `prove()` per context incl. implicit contexts, with golden flows first; ProofResult (pass with coverage + unhit rules + seed, or the shrunk counterexample with both decisions and zones)
  - _Requirements: 6.3, 6.4, 6.6, 6.8_
- [ ] 8.3 Mutation sanity suite: every playbook mutant must fail P2 with a counterexample
  - _Requirements: 6.7_
- [ ] 8.4 Performance check: 10k examples per sample under 15 s; 5k-rule synthetic config parse + autopsy under 5 s
  - _Requirements: 6.5, 8.1_

- [ ] 9. Interfaces
- [ ] 9.1 Grimoire report (see migration-governance tasks)
  - _Requirements: 7.1_
- [ ] 9.2 FastAPI `/v1` endpoints + `/healthz` + mangum handler + limits + structured errors + security headers
  - _Requirements: 7.2, 7.5_
- [ ] 9.3 MCP server (`FastMCP`, stdio) with tools exhume/autopsy/resurrect/prove/gate; register in `.kiro/settings/mcp.json`
  - _Requirements: 7.3_
- [ ] 9.4 `necro` CLI with formats, seed, profile and exit codes
  - _Requirements: 7.4_

## Phase 2: enterprise hardening

- [ ] 10. ASA 8.3–9.x (`asa_objects.py`): object network/service, object NAT, twice NAT (static), any4, global ACL; golden flows `asa-9.8-dc.toml`; PBT P13
  - _Requirements: 1.13, 2.6, 4.12_
- [ ] 11. Time-range → PAN-OS schedule objects
  - _Requirements: 4.13_
- [ ] 12. Hit-count ingestion (`show access-list`) and zero-hit findings; correlated-rule findings
  - _Requirements: 1.14, 3.11, 3.12_
- [ ] 13. PAN-OS NAT policy emission (static, PAT) and Panorama/XML output options
  - _Requirements: 4.12, 4.15_

## Stretch
- [ ]* 14. Cisco ISE TrustSec SGACL matrix emitter (SGT per object-group, SGACL per rule)
- [ ]* 15. Check Point R65 parser (done as a **vibe-coded** spike first, for the spec-vs-vibe comparison)
