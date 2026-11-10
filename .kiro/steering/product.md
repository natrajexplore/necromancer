---
inclusion: always
---

# Product: NECROMANCER

**One-liner:** Raise dead firewall configs as zero-trust policy, and prove they came back the same.

## Users
- Network/security engineers migrating end-of-life firewalls (Cisco PIX 6.x, ASA 7.x–9.x, IOS 12 ACLs) to modern platforms (PAN-OS first).
- Change approvers (CAB, security architects, auditors) who need objective evidence before they sign.
- MSPs and consultancies running many migrations, who need an auditable report for change advisory boards.

## Core journey (the "ritual")
1. **Exhume**: upload or paste a dead config. It appears as a tombstone in the Graveyard.
2. **Autopsy**: find ghost rules (shadowed, redundant, any-any, insecure services, unused objects).
3. **Resurrect**: translate to the vendor-neutral IR, then emit a PAN-OS candidate config. Optional zero-trust tightening.
4. **Proof of Life**: a property-based oracle checks original vs resurrected behaviour over generated flows. Shows a pass, or the smallest counterexample packet.
5. **Verdict + Grimoire**: gates G1–G6 give a GO / CONDITIONAL / NO-GO verdict. Download the migration report (verdict, findings, config, proof, exorcism ledger, runbook).

## Product principles
- **Correctness beats cleverness.** Never emit policy that wasn't proven, or whose divergences aren't all listed in the exorcism ledger.
- **Like-for-like first, tighten second.** The baseline migration preserves behaviour exactly. Zero-trust tightening is a separate artifact with its own ledger and proof.
- **Nothing silent.** Every input line is accounted for. Unsupported constructs block the verdict until a named human waives them.
- **Evidence, not claims.** The tool says "supports evidence for" a control, never "compliant" or "safe to deploy". It never connects to devices.
- **Spooky skin, serious output.** The UI is themed. The report, config and CLI output are plain and professional.
- **Deterministic core.** No LLM is needed for parse, translate or prove. An LLM may only *explain*.
- **Free to judge.** The hosted demo must work with no login and no API keys.
- **Synthetic data only.** Never include real customer or employer configurations.
