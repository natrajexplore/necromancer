---
inclusion: always
---

# Repository structure

```
/.kiro/                   Kiro specs, steering, hooks, agents, MCP settings (never gitignore)
/backend/
  necro/
    ir.py                 Vendor-neutral policy IR (pydantic models)
    sets.py               PortSet / AddrSet interval algebra (normalize, contains, intersect, subtract, covers)
    masks.py              Subnet <-> wildcard conversion, contiguity checks
    names.py              (protocol, name) -> port / ICMP type / IP protocol tables
    redact.py             Secret redaction (runs before anything else sees the text)
    evaluate.py           decide(policy, ctx, flow) -> Decision. Single source of truth for semantics
    zones.py              Route table + longest-prefix match -> to_zone ("self" for device IPs)
    nat.py                NAT model and address-space mapping (mapped / real / pre-NAT)
    coverage.py           Line classification and coverage accounting
    parsers/
      detect.py           Dialect + version + mode detection with confidence
      cisco_common.py     Shared tokenizer, address/port operand parsing
      pix_asa.py          PIX 6.x / ASA 7.x-8.2 (names, object-groups, ACLs, access-group, static/nat/global)
      asa_objects.py      ASA 8.3+ object / object-group / object NAT / global ACL
      ios_acl.py          IOS 12 standard + extended ACLs, bindings, ACL classification
      panos_reader.py     Parses emitted PAN-OS set commands back into IR (used by the oracle)
    emitters/
      panos.py            PAN-OS set-command emitter (zones, objects, rules, NAT, schedules, mgmt profiles)
      panos_names.py      Deterministic, collision-free PAN-OS identifiers
    validate_panos.py     Gate G3 static checks on emitted PAN-OS
    autopsy.py            Ghost-rule findings
    tighten.py            Zero-trust tightening + exorcism ledger
    oracle.py             Proof of Life (Hypothesis strategies + runner)
    gates.py              Gates G1-G6 + readiness verdict
    runbook.py            Pre-check / cutover / verification / rollback command lists
    report.py             Grimoire (Markdown + HTML report)
    cli.py                `necro` CLI
  api/main.py             FastAPI app (+ mangum handler)
  mcp_server.py           MCP server exposing exhume/autopsy/resurrect/prove/gate
  tests/                  pytest + hypothesis (mark PBT tests with @pytest.mark.pbt)
/frontend/                React graveyard UI
/samples/
  dead-configs/           Synthetic EOL configs with seeded "! GHOST:" rules
  broken-configs/         Negative fixtures (cycles, undefined groups, unsupported constructs, out-of-scope modes)
  golden-flows/           Hand-verified expected decisions (TOML), independent of evaluate.py
/crew/                    Kiro Crew Seance workflow notes + artifacts
/docs/                    Rules analysis, plan, write-up, video script, Devpost draft
/.github/workflows/       CI (lint, types, tests, PBT ci profile, audit)
```

## Rules
- `redact.py` runs first. No other module ever sees unredacted text.
- Parsers return IR only. They never emit vendor config.
- Emitters consume IR only. They never read raw config.
- `evaluate.py` is the single source of truth for semantics: autopsy, gates and the oracle all call it.
- Golden flows are never generated from `evaluate.py` output. They're written and reviewed by hand.
- One module = one responsibility. Split files over ~400 lines.
