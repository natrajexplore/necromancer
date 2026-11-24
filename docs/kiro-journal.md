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

## 2026-11-24 — CLI
- Spec task(s): necro-engine/8.1, 8.2, 8.3, 8.4
- What Kiro did: Fixed a seed-dependent coverage flake, added the 10-mutant suite (which exposed three oracle gaps, now fixed) and cut 5,000-rule autopsy from 249 s to 1.3 s.
- What the human corrected: Nothing; Kiro found 8.1-8.2 already committed plus uncommitted edits it did not make, and committed those in 8.3 (noted in the commit).
- Kiro feature used: specs, hooks, steering, agent, PBT

## 2026-11-24 — CLI
- Spec task(s): necro-engine/9.2, 9.3, 9.4
- What Kiro did: Added the /v1 API with limits and headers, the FastMCP stdio server and the necro CLI over one shared service layer; pinned mcp<2 for FastMCP.
- What the human corrected: Nothing yet; writes to .kiro/settings/mcp.json were denied, so 9.3 registration is pending.
- Kiro feature used: specs, hooks, steering, MCP

## 2026-11-24 — CLI
- Spec task(s): migration-governance/6-9, necro-engine/9.1 (not started)
- What Kiro did: Found that governance tasks 1-5 (models, gates, verdict) do not exist, so 6-9 and 9.1 are blocked; asked which option to take instead of changing code.
- What the human corrected: Nothing yet; waiting for the scope decision.
- Kiro feature used: specs, agent

## 2026-11-24 — CLI
- Spec task(s): migration-governance/6-9, necro-engine/9.1 (not started)
- What Kiro did: Found uncommitted gate_models.py and its tests from another running session (governance task 1) and stopped to avoid colliding with its work.
- What the human corrected: Nothing yet; waiting for which session owns governance 1-5.
- Kiro feature used: specs, agent

## 2026-11-24 — CLI
- Spec task(s): graveyard-ui/1, graveyard-ui/2, graveyard-ui/3
- What Kiro did: Built frontend/ (Vite + React 18 + TS + Tailwind 4): tokens with a WCAG AA test, OFL fonts, reduced motion, React Query API client, and the Graveyard screen with unquiet lines; checked it against the live backend.
- What the human corrected: Nothing; the push also published another session's unpushed governance commits after their checks passed.
- Kiro feature used: specs, steering, hooks

## 2026-11-24 — CLI
- Spec task(s): graveyard-ui/4-7 (not started)
- What Kiro did: Mapped the screens to the v1 API and found gaps (rule lists, zone map, tighten endpoint, haunt option, gate/grimoire still 501); proposed the backend additions and asked before editing files the governance session also edits.
- What the human corrected: Nothing yet; waiting on two decisions (shared backend edits, task 7 timing).
- Kiro feature used: specs, steering

## 2026-11-24 — CLI
- Spec task(s): graveyard-ui/7 (status check)
- What Kiro did: Confirmed task 7 is not done or started: graveyard-ui 4-7 and governance 5-9 are unticked, and /v1/gate and /v1/grimoire still return 501.
- What the human corrected: Nothing; asked for status only.
- Kiro feature used: specs

## 2026-11-24 — CLI
- Spec task(s): graveyard-ui/4-7 (on hold)
- What Kiro did: Put graveyard-ui task 7 on hold until governance tasks 7-9 land; tasks 4-6 also held pending OK for shared backend edits.
- What the human corrected: Chose to wait for task 7 instead of building it unticked.
- Kiro feature used: specs

## 2026-11-24 — CLI
- Spec task(s): migration-governance/1-5
- What Kiro did: Built governance models, G3 PAN-OS static checks, gates G1-G6 and the verdict (waiver expiry, four-eyes, forbidden-words test); pushed 5 commits.
- What the human corrected: Nothing; Kiro's own fixes were the service-group fixture syntax, dropping themed finding labels from gate text, and waiting for the coverage run before editing.
- Kiro feature used: agent (gatekeeper), specs, steering, hooks, PBT
