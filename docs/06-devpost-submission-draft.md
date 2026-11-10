# Devpost submission draft

**Project name:** NECROMANCER
**Tagline:** Raise dead firewall configs as zero-trust policy, and prove they came back the same.
**Category:** Resurrection
**Bonus prizes entered:** Best Startup Project · Best Kiro Crew App · Best Demo (automatic) · Bonus Blog · Social Blitz
*(Add Ghost of Kiroween Past only if you have proof of Kiroween 2025 registration.)*

## Inspiration
Enterprises still run firewalls that went end-of-life years ago: PIX, ASA 8.x, IOS 12 routers with thousands of ACL lines. Migration stalls because nobody can prove the new policy behaves like the old one. One wrong rule means an outage or a breach.

## What it does
1. **Exhume**: parse PIX/ASA/IOS configs into a vendor-neutral IR. Secrets are redacted.
2. **Autopsy**: find ghost rules: shadowed, redundant, overly broad, insecure services, unused objects.
3. **Resurrect**: emit PAN-OS candidate config, with optional zero-trust tightening recorded in an exorcism ledger.
4. **Proof of Life**: a property-based oracle checks equivalence over 10,000 generated flows and shows the shrunk counterexample if anything diverges.
5. **Verdict + Grimoire**: six validation gates give a GO / CONDITIONAL / NO-GO verdict, plus a migration report and cutover/rollback runbook ready for a change advisory board.

## How we built it
Spec-driven in Kiro (3 specs, __ tasks), 8 steering docs across 3 inclusion modes, 6 v1 hooks, 5 custom agents, a custom MCP server, and a Kiro Crew "Séance" workflow. Python/FastAPI/Hypothesis backend, React haunted UI, on AWS Lambda + S3.

## Challenges
Exact ACL semantics (subnet vs wildcard masks, nested object-groups, `established`, `neq`, security levels, pre-8.3 vs 8.3+ NAT addresses mapped to PAN-OS pre-NAT IP + post-NAT zone), and making the proof meaningful by comparing against the *re-parsed emitted config* rather than the in-memory IR.

## Accomplishments
__ seeded ghosts found with 100% recall. 10,000-flow proof in __ s. The oracle catches a single swapped operator.

## What's next
Cisco ISE TrustSec SGACL output, Check Point and FortiOS parsers, traffic-log-driven tightening, and a commercial MSP edition.

## Testing instructions for judges
URL: __ (no login). Click any tombstone → Autopsy → Resurrect → Prove. Turn on "Haunt it" to see a counterexample. Use only synthetic configs.

## Links
- Repo: https://github.com/natrajexplore/necromancer
- Video: __
- Kiro Crew repo/link: __
- Startup site: __ · Founder LinkedIn: https://linkedin.com/in/nataraj-angappan-3a8614138
