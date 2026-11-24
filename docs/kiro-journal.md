# Kiro Journal

## 2026-11-16 — CLI
- Spec task(s): none (vibe)
- What Kiro did: Responded to CLI session start with a greeting and project context offer
- What the human corrected: none
- Kiro feature used: hooks

## 2026-11-16 — CLI
- Spec task(s): necro-engine/1
- What Kiro did: Scaffolded backend/ (pyproject.toml, .python-version, necro/__init__.py) before being interrupted by steering injection
- What the human corrected: none yet — task still in progress
- Kiro feature used: specs/steering/hooks

## 2026-11-16 — CLI
- Spec task(s): necro-engine/1
- What Kiro did: Ran pytest coverage gate; 3 passed, 100% coverage, exit 0
- What the human corrected: none
- Kiro feature used: specs/hooks

## 2026-11-16 — CLI
- Spec task(s): necro-engine/1
- What Kiro did: Ran ruff format --check; 6 files already formatted, exit 0
- What the human corrected: none
- Kiro feature used: specs/hooks

## 2026-11-16 — CLI
- Spec task(s): necro-engine/2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3
- What Kiro did: Implemented sets.py (PortSet/AddrSet with P9 PBT), ir.py (full vendor-neutral IR), masks.py (subnet/wildcard with P7 PBT), names.py (protocol-keyed tables with 514/512/radius trap tests), redact.py (all security patterns with P10 PBT), zones.py (route table + LPM), evaluate.py (decide() with full PIX/ASA/IOS semantics and P8 PBT), nat.py (pre-8.3 NAT model). 174 tests, 95.97% coverage. ruff/format/mypy all green.
- What the human corrected: none
- Kiro feature used: specs/steering/hooks

## 2026-11-16 — CLI
- Spec task(s): none (vibe)
- What Kiro did: Responded to session start hook; no task executed
- What the human corrected: none
- Kiro feature used: hooks

## 2026-11-16 — CLI
- Spec task(s): necro-engine/2.1, 2.3, 2.5, 3.2
- What Kiro did: Ran pytest -q -m pbt; 18 PBT tests (P7, P8, P9, P10) passed in 5.7 s at dev profile
- What the human corrected: none
- Kiro feature used: PBT/hooks

## 2026-11-21 — CLI
- Spec task(s): necro-engine/3.2
- What Kiro did: Fixed egress ACL semantics in evaluate.py (implicit deny, Policy.egress_acls by to_zone, no swallowed errors), added tests, pushed ddc0999
- What the human corrected: none
- Kiro feature used: PBT/hooks

## 2026-11-21 — CLI
- Spec task(s): necro-engine/4.1, 4.2, 4.3, 4.4, 4.5, 4.6 (plus fix to 2.5)
- What Kiro did: Built PIX/ASA and IOS parsers, detection, line accounting, renderers with P1/P14, and golden-flow tests; fixed evaluator zone bugs and an SNMP redaction leak; pushed 447336a
- What the human corrected: none
- Kiro feature used: specs/steering/hooks/PBT

## 2026-11-21 — CLI
- Spec task(s): necro-engine/5.1, necro-engine/5.2
- What Kiro did: Built the Autopsy engine (box-algebra shadowed/redundant plus nine other finding types, zone-trust severity), confirmed via decide(), 100% recall on seeded GHOST lines.
- What the human corrected: Nothing this session; Kiro found and fixed an undefined-ACL fixture in its own test and flagged an evaluator same-security gap for a follow-up.
- Kiro feature used: specs, hooks, steering, PBT

## 2026-11-21 — CLI
- Spec task(s): necro-engine/6.1, 6.2, 6.3, 6.4, 6.5, 6.6
- What Kiro did: Built the PAN-OS emitter, exorcism ledger and reader, and ran generated-policy equivalence checks that found and fixed three emitter bugs.
- What the human corrected: Nothing this session; Kiro dropped the Hypothesis deadline on the P3 tests after a timing failure under coverage.
- Kiro feature used: specs, hooks, steering, PBT

## 2026-11-21 — CLI
- Spec task(s): necro-engine/6.1-6.6 (re-requested)
- What Kiro did: Confirmed 6.1-6.6 were already ticked, committed and pushed, and pushed the pending journal commit (462d555).
- What the human corrected: Nothing; the request repeated finished work.
- Kiro feature used: specs, hooks

## 2026-11-24 — IDE
- Spec task(s): necro-engine/7
- What Kiro did: Added tighten.py and tighten_regions.py (remediations, ledger with approvals, separate tightened artifact) and PBT P6; all gates green at 98% coverage.
- What the human corrected: Nothing; Kiro corrected its own tasks.md encoding damage in a follow-up commit.
- Kiro feature used: specs, steering, hooks, PBT
