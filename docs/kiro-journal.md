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
