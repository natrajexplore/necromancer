---
inclusion: fileMatch
fileMatchPattern: ["backend/necro/report*.py", "backend/necro/gates/**/*.py", "backend/necro/runbook*.py", "backend/necro/validate_panos*.py", "backend/tests/test_gates*.py", "frontend/src/**/Grimoire*", "frontend/src/**/Verdict*", "docs/**/*.md"]
---

# Migration governance: the mandatory steps

NECROMANCER produces **evidence for a change**, not a change. It never connects to devices. These are the
steps that enterprise firewall migrations (Cisco ASA/PIX/IOS → Palo Alto) follow in regulated environments.
The Grimoire report and the readiness verdict must show which steps are done, which are evidenced by the
tool, and which a named human still owes.

Wording rule: the tool says **"supports evidence for"** a control. It never says "compliant" or "safe to deploy".

## 1. Phases (each one ends with an exit criterion)

| # | Phase | Mandatory activities | Exit criterion | Tool support |
|---|---|---|---|---|
| P0 | Scope & inventory | Device, model, OS version, mode (routed/transparent, single/multi-context), interfaces, zones, routes, NAT, VPN, HA, features in use. Name owners for each zone and application | Signed scope listing in-scope and out-of-scope features (VPN, dynamic routing, AAA, IPS, QoS are **out** of policy migration) | Exhume detects version, mode and features. Out-of-scope features are listed |
| P1 | Baseline capture | `show running-config`, `show access-list` (hit counts), `show nat` / `show xlate`, `show route`, `show version`, captured in the same window. Record the SHA-256 and capture time | Baseline is less than 7 days old at cutover, or re-captured | Input SHA-256 in every report. Hit counts optional (Phase 2) |
| P2 | Pre-migration hygiene (autopsy) | Review shadowed, redundant, overly broad, insecure, unused and zero-hit rules **with the rule owners** | Every critical/high finding has a decision: fix, accept (with an expiry) or carry forward | Autopsy findings with severity, plus a decision column |
| P3 | Translation (like-for-like) | Port-based, behaviour-preserving translation. **No policy changes mixed in** | Candidate config with zero unexplained divergences | Resurrect (baseline output) |
| P4 | Validation | Gates G1–G6 (§2). Static checks, equivalence proof, golden flows, ledger review | Verdict = GO, or CONDITIONAL with named waivers | Gates engine + Proof of Life |
| P5 | Peer review & CAB | Four-eyes review by an engineer who didn't do the translation. A change record with risk, impact, test evidence, schedule, rollback and communication plan | CAB approval reference recorded | Grimoire is the evidence pack. The change ID and approver are recorded on the verdict |
| P6 | Pre-cutover checks | Load the candidate on the target in `configure` mode and run `validate full` (commit validation) **without committing**. Check interface/zone mapping, routes, NAT, HA sync, log forwarding to the SIEM, and config backups of **both** source and target | All pre-checks ticked, with evidence attached | Runbook generates the pre-check list |
| P7 | Cutover | In the approved window: change freeze on the source, apply, commit, run the verification flows on the target (`test security-policy-match ...`), compare with the source baseline (`packet-tracer ...` on ASA ≥ 7.2) | All verification flows match the expected decisions | Runbook generates both command lists from the golden flows plus a sample of oracle flows |
| P8 | Post-checks & hypercare | Watch deny logs, rule hit counts, application owner sign-off. Hypercare period (default 10 business days) | Owners sign off. No unexplained denies | Report lists the rules to watch (ledger entries, low-coverage rules) |
| P9 | Rollback | Pre-defined triggers (e.g. a P1 incident, verification mismatch, owner request), a time limit for the decision, and exact rollback steps (re-cable/re-route back to the source, restore the target backup) | Rollback tested or walked through before the window | Runbook includes a rollback section with triggers |
| P10 | Optimization (separate changes) | Zero-trust tightening, App-ID conversion (Policy Optimizer), unused-rule removal. **Each is its own change** with its own proof | Each tightening change has a ledger and a passing proof | Tighten produces a separate output and ledger |
| P11 | Decommission | Source removed from production, configs archived per the retention policy, CMDB/IPAM updated, credentials rotated (shared secrets on the old device are considered exposed) | Decommission record | Report checklist item |

Rules that the tool enforces:
- **R1.** Baseline (like-for-like) and tightened outputs are separate artifacts with separate proofs. The UI and API
  never deliver a tightened config without its ledger.
- **R2.** No GO verdict while any security-relevant line is unparsed and unwaived.
- **R3.** No GO verdict without a passing equivalence proof at the `ci` budget (≥ 5,000 examples per context) **and** 100% golden-flow pass.
- **R4.** Every ledger entry has a reason, a finding reference, a declared decision and an approval state. `pending` blocks GO.
- **R5.** Every waiver has an approver name, a reason and an expiry date. Expired waivers block GO.
- **R6.** Reports are deterministic. The same input, options and seed produce byte-identical outputs (timestamps live only in the header).
- **R7.** Shared secrets found in the source (PSKs, SNMP communities, TACACS/RADIUS keys) are redacted, and the report
  recommends rotating them, because they're considered exposed once the device is decommissioned.

## 2. Validation gates

| Gate | Checks | Blocks GO when |
|---|---|---|
| **G1 Input integrity** | SHA-256 recorded, dialect detected with confidence ≥ 0.9, OS version in the supported list, mode = routed single-context | Any check fails |
| **G2 Coverage** | Every input line classified: `migrated`, `not-policy` (hostname, banner, ...), `management-plane`, `out-of-scope`, `unparsed`. Coverage % = migrated ÷ security-relevant lines | Any security-relevant line is unparsed or out-of-scope and not waived |
| **G3 Target static validation** | PAN-OS names valid/unique/≤ 63 chars, every reference resolves, no empty groups, every rule has from/to zone, explicit final deny present, no duplicate rule names, no `any`→`any` allow without a ledger entry | Any error (warnings don't block) |
| **G4 Equivalence** | P2 passes per context at the `ci` budget or higher. Every **active** rule hit at least once on both sides (rules not hit are listed). All golden flows pass | Any divergence outside the ledger, or a golden-flow failure |
| **G5 Ledger review** | Every entry has an approval state of `accepted` or `rejected`. Rejected tightenings aren't in the output | Any `pending` entry |
| **G6 Risk findings** | No open `critical` finding without an accepted-risk record (approver + expiry) | Any unaccepted critical |

**Verdict** = `GO` (all gates pass), `CONDITIONAL` (passes only because of valid waivers or accepted risks, all listed
on the first page), or `NO-GO` (anything else, with the blocking reasons first).

## 3. Severity model (autopsy)

| Severity | Meaning | Examples |
|---|---|---|
| critical | Exposure from an untrusted zone (security level 0, or an interface named outside/internet/partner) to sensitive services, or `permit ip any any` from untrusted | telnet/rsh/tftp/snmp v1-v2c/RDP/SMB from outside, any-any from outside |
| high | Broad or insecure access between internal zones; cleartext management; unfiltered interfaces | any-any from DMZ, ftp from outside, telnet on vty, interface without an ACL |
| medium | Hygiene that hides intent or risk | shadowed/redundant rules, partial overlaps with the opposite action, return-traffic rules |
| low | Housekeeping | unused objects, rules without a remark (no business justification) |

## 4. Control mapping (supports evidence for)

| Framework | Control | How the Grimoire supports evidence |
|---|---|---|
| PCI DSS v4.0 | 1.2.1 configuration standards for NSCs; 1.2.2 changes approved per change control; 1.2.5 services/ports identified, approved, with business need; 1.2.6 insecure services secured; 1.2.7 NSC rules reviewed at least every six months; 1.2.8 config files secured | Rule inventory with remark/justification column, insecure-service findings, proof plus change record fields, redacted config handling |
| NIST SP 800-41 Rev. 1 | Firewall policy lifecycle (plan, configure, test, deploy, manage); default-deny | Phases P0–P11, explicit final deny, test evidence |
| NIST SP 800-53 Rev. 5 | CM-3 configuration change control; CM-4 impact analysis; AC-4 information flow enforcement; SC-7 boundary protection | Ledger (impact of each change), equivalence proof, zone-to-zone matrix |
| ISO/IEC 27001:2022 Annex A | 8.9 configuration management; 8.20 networks security; 8.32 change management | Deterministic baseline, hashes, change record, gates |
| CIS Controls v8 | 4 secure configuration; 12 network infrastructure management; 13 network monitoring and defense | Insecure-management findings, logging on all rules, final deny with logging |

The table is guidance for auditors. Control applicability is always decided by the organization's own assessor.

## 5. Grimoire report: required sections (in order)
1. **Verdict page**: GO / CONDITIONAL / NO-GO, gate table, blocking reasons, waivers, change ID, approvers.
2. **Audit header**: tool version and git commit, input SHA-256 per file, dialect + OS version, options, seed,
   example budget, profile, UTC timestamp, output SHA-256.
3. **Scope & assumptions**: in- and out-of-scope features, address-space model, zone mapping table (interface → zone, security level).
4. **Coverage**: line classification counts, and the list of every unparsed, waived or out-of-scope line with its reason.
5. **Findings**: by severity, each with rule reference, explanation, recommendation and a decision column.
6. **Exorcism ledger**: every entry with class, reason, affected match, old/new decision and approval.
7. **Proof of Life**: per-context examples, divergences, rule coverage on both sides, golden-flow results, seed.
8. **Zone-to-zone matrix**: allowed services between each zone pair (before and after).
9. **Runbook**: pre-checks, cutover steps, verification commands (target and source), rollback triggers and steps, post-checks.
10. **Appendix**: emitted PAN-OS config (baseline, and tightened if any) and the redacted source config.

Plain, professional language only. No spooky theme in the report.
