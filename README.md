# 🕯️ NECROMANCER

**Raise dead firewall configs as zero-trust policy, and prove they came back the same.**

*Kiroween 2026 · Category: **Resurrection** · Built with Kiro*

Every enterprise has a graveyard: Cisco PIX, ASA 8.x and IOS 12 devices that went end-of-life years ago but still guard production, because nobody can prove a rewrite of thousands of rules is safe. NECROMANCER:

| Ritual | What happens |
|---|---|
| ⚰️ **Exhume** | Parse PIX 6.x / ASA ≤ 8.2 / IOS 12 extended ACLs into a vendor-neutral IR (secrets redacted) |
| 🔪 **Autopsy** | Find ghost rules: shadowed, redundant, any-any, insecure services, unused objects |
| 🧟 **Resurrect** | Emit a PAN-OS candidate config, with optional zero-trust tightening tracked in an exorcism ledger |
| 💓 **Proof of Life** | A property-based oracle (Hypothesis) checks equivalence over 10,000 boundary-biased flows, or shows the shrunk counterexample |
| 🚦 **Verdict** | Validation gates G1–G6 (input integrity, coverage, PAN-OS static checks, equivalence, ledger review, risk) give GO / CONDITIONAL / NO-GO |
| 📖 **Grimoire** | A migration report and cutover/rollback runbook for your change advisory board |

## Migration semantics it gets right
The classic ASA/IOS → PAN-OS traps are pinned down in [`policy-semantics.md`](.kiro/steering/policy-semantics.md) and tested with hand-verified vectors in [`samples/golden-flows/`](samples/golden-flows):

- ASA/PIX security-level implicit permits, the same-security restriction, PIX nat-control, the ASA 9.x global ACL
- Pre-8.3 (mapped) vs 8.3+ (real) ACL addresses mapped to PAN-OS pre-NAT IP + post-NAT zone
- Destination zones from the route table, with rules split per zone
- IOS `established` vs PAN-OS sessions, permit-all on interfaces without an ACL, to-the-box traffic → management profiles
- Port names keyed by protocol (514/tcp ≠ 514/udp, Cisco `radius` = 1645), exact ICMP types (no silent widening to `ping`)
- Every input line accounted for. IPv6, FQDN objects, transparent mode and other unsupported constructs block the verdict instead of disappearing

The mandatory migration phases (scope → baseline → hygiene → like-for-like translation → validation → peer review/CAB → pre-checks → cutover → hypercare → rollback → optimization → decommission) are in [`migration-governance.md`](.kiro/steering/migration-governance.md). It also maps the evidence to PCI DSS v4.0, NIST SP 800-41/800-53, ISO/IEC 27001:2022 and CIS Controls v8 as "supports evidence for", not a compliance claim.

## Status
🚧 Under construction during the Kiroween submission period (Oct 30 – Dec 4, 2026). The implementation is driven by the Kiro specs in [`.kiro/specs/`](.kiro/specs).

## Repository map
```
.kiro/specs/        necro-engine + migration-governance + graveyard-ui (requirements → design → tasks)
.kiro/steering/     product, tech, structure, security (always) · policy-semantics, migration-governance, haunted-ui (fileMatch) · pbt-playbook (manual)
.kiro/hooks/        proof-of-life, ghost-rule-guard, readiness-gate-guard, secret-exorcist, spec-traceability, kiro-journal-on-stop (v1 JSON)
.kiro/agents/       ghoul-parser, autopsy-surgeon, necromancer, oracle, gatekeeper
.kiro/settings/     mcp.json (custom necromancer MCP server + fetch)
samples/dead-configs/    synthetic PIX 6.3 / ASA 8.2 / ASA 9.8 / IOS 12.4 configs with seeded "! GHOST:" rules
samples/broken-configs/  negative fixtures (cycles, undefined groups, unsupported constructs, out-of-scope modes)
samples/golden-flows/    hand-verified expected decisions (TOML), independent of the evaluator
crew/               Kiro Crew "Séance" workflow
docs/               rules analysis, idea selection, build plan, Kiro write-up, video script, Devpost draft
```

## Quick start (once implemented)
```bash
cd backend && uv sync && uv run pytest -q          # incl. property-based tests
uv run necro prove ../samples/dead-configs/pix-2006-hq.cfg --profile demo
uv run necro gate  ../samples/dead-configs/pix-2006-hq.cfg --sidecar approvals.toml   # exit 0 = GO/CONDITIONAL, 1 = NO-GO
npm --prefix frontend install && npm --prefix frontend run dev
```

## Data notice
All sample configs are **synthetic** (RFC 5737 / RFC 1918 addresses, fake secrets). The hosted demo processes uploads in memory and stores nothing. NECROMANCER never connects to or pushes configuration to any device: it produces a candidate config and evidence for human review. Vendor names are used only to describe compatibility. This project isn't affiliated with or endorsed by any vendor.

## Disclosure
Planning documents and the initial spec drafts were prepared with Claude before implementation began. All application code is generated and iterated in Kiro. Third-party libraries are listed in `backend/pyproject.toml` and `frontend/package.json`.

## License
MIT. See [LICENSE](LICENSE).
