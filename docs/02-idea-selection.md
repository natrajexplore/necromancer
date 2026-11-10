# Idea Selection — Why NECROMANCER

## Selection principles (from the rules + your edge)

1. **Win all 5 criteria evenly.** Each one is 20%, so a flashy idea with weak impact loses.
2. **Domain unfair advantage.** 10+ years in Cisco ISE, Palo Alto, Check Point, wireless and Zero Trust. Judges rarely see deep network-security tools. Most entries will be generic web apps.
3. **PBT should be native to the idea, not bolted on.** The rules name property-based testing as a scored write-up topic.
4. **Multi-agent work fits the problem naturally**, which opens the Kiro Crew bonus.
5. **There's a startup story**, which opens the $10k Startup bonus and supports your consulting plans.
6. **Solo-buildable in 25 days**, with a deterministic core so it stays judgeable for free.

## Candidates scored (1–10)

| Idea | Category | Impact | Kiro depth | Design | Innovation | Demo | Total |
|---|---|---|---|---|---|---|---|
| **NECROMANCER** — raise dead firewall configs (PIX/ASA 8.x/IOS 12) as zero-trust PAN-OS policy, **proven equivalent with property-based testing** | Resurrection | 9 | 10 | 8 | 9 | 9 | **45** |
| OUIJA-OPS — talk to legacy gear (SNMPv1, syslog, telnet-only switches) via an MCP "séance" bridge to an LLM NOC agent | Frankenstein | 8 | 9 | 7 | 8 | 8 | 40 |
| HAUNTED SPECTRUM — RF "ghost" detector: Wi-Fi scan data shown as hauntings (rogue APs, co-channel interference) | Costume Contest | 6 | 7 | 10 | 7 | 9 | 39 |
| NETOPS SKELETON — a template for network-automation agents with two apps (WLC DR check + ISE policy audit) | Skeleton Crew | 7 | 9 | 6 | 6 | 6 | 34 |

**Pick: NECROMANCER (Resurrection).** OUIJA-OPS is the backup if you find a teammate.

## The pitch

> *"Every enterprise has a graveyard: firewalls that went end-of-life a decade ago but still guard production, because nobody dares migrate 4,000 rules by hand. NECROMANCER raises them. It exhumes the dead config, performs an autopsy to find the ghost rules, resurrects it as zero-trust policy on a modern platform — and then proves, with 10,000 generated packets, that it came back the same. Anything it changed on purpose is listed, with a reason."*

## What makes it new

1. **Proof of Life (the PBT oracle).** The tool doesn't just translate. It checks semantic equivalence. Hypothesis generates random and boundary-biased 5-tuples (src, dst, proto, sport, dport) and evaluates them against the original first-match ACL and the resurrected policy. It returns `0 divergences / 10,000 flows`, or the **smallest counterexample packet** (Hypothesis shrinking). Migration tools don't usually do this.
2. **Intentional divergence ledger.** Zero-trust tightening (removing `any any`, closing telnet/tftp/snmp-v1) deliberately changes behaviour. Each change is recorded as an *exorcism* with its reason, and the oracle checks that **only** the listed flows changed.
3. **Ghost-rule autopsy.** Shadowed, redundant, overly broad and dead-object rules are found by the same evaluator, so the analysis and the proof share one source of truth.
4. **A spooky UI on top of serious output.** The graveyard is how you navigate. The output is a professional migration report you could hand to a change advisory board.

## Scope

**MVP (must ship by Nov 30):**
- Parsers: Cisco PIX 6.x / ASA 8.x `access-list` + `object-group` + `name` + `access-group`. IOS 12 numbered and named extended ACLs.
- Policy IR (vendor-neutral, pydantic) plus a first-match evaluator.
- Emitter: PAN-OS `set` commands (zones, address and service objects, security rules).
- Autopsy: shadowed / redundant / any-any / insecure-service / unused-object findings.
- Proof of Life: Hypothesis PBT oracle (CLI + API + UI), with a counterexample viewer.
- Exorcism ledger plus the zero-trust tightening pass.
- Graveyard UI plus a downloadable "Grimoire" migration report (Markdown → PDF).
- Custom MCP server exposing `exhume`, `autopsy`, `resurrect`, `prove`.

**Stretch (only after the MVP is green):**
- Cisco ISE TrustSec SGACL matrix emitter (your ISE specialty, and a strong "future problem" angle).
- Check Point R65 (EOL) parser.
- Optional LLM "Medium" that explains findings in plain English, behind a toggle with cached examples so judges never need a key.

## Avoid
- Real customer or employer configs, anywhere.
- Copying code from your earlier projects (ConfigGuard, the CrewAI FW change reviewer). That breaks the new-work rule.
- Vendor logos or brand marks in the UI or video.
