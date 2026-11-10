# Demo video script, target 2:45 (hard limit < 3:00)

Rules: public YouTube, shows the real app running, **no copyrighted music** (use self-made or royalty-free tracks you have a licence for), **no vendor logos**.

| Time | Visual | Voice-over |
|---|---|---|
| 0:00–0:15 | Fog, graveyard, three tombstones: "PIX · died 2013", "ASA 8.2 · died 2016", "IOS 12 · died 2016" | "Every enterprise has a graveyard: firewalls that died years ago but still guard production, because nobody dares rewrite thousands of rules by hand." |
| 0:15–0:25 | Title: **NECROMANCER**, "raise dead firewalls — with proof" | "NECROMANCER raises them, and proves they came back the same." |
| 0:25–0:55 | Drop `pix-2006-hq.cfg` → Autopsy view, ghosts float over rows. Click the shadowed rule to highlight the rule shadowing it. Telnet ghost glows red | "Autopsy first. It finds shadowed rules that never fire, any-any permits, telnet from the internet, and dead objects. Every ghost gets a plain-English reason." |
| 0:55–1:20 | Resurrect → rising animation → split view original vs PAN-OS. Toggle tightening: telnet → ssh, remove the shadowed rule. Ledger fills in | "Resurrection produces a PAN-OS candidate config. Zero-trust tightening is optional, and every behaviour change is written to an exorcism ledger. Nothing changes silently." |
| 1:20–1:50 | Proof of Life: heartbeat runs, `10,000 flows · 0 divergences · rule coverage 100% / 100%` | "Then the proof. Property-based testing generates ten thousand boundary-biased packets and checks the old and new policy decide the same way, except for the changes we chose." |
| 1:50–2:10 | Toggle "Haunt it" (broken emitter) → red card: **the packet that refused to rest** `tcp 203.0.113.7:1024 → 192.168.50.10:80` with both decisions | "Break the emitter and the oracle catches it immediately, then shrinks the failure to the single packet that proves the bug." |
| 2:10–2:30 | Quick cuts: `.kiro/specs` tasks ticking, a hook firing on save, Kiro chat calling `@necromancer/prove` over MCP, Crew Activity view with an approval gate | "Built spec-first in Kiro: five custom agents, hooks that run the proof on every save, our own MCP server, and a Kiro Crew séance that re-proves every config nightly." |
| 2:30–2:45 | Verdict banner turns from **NO-GO** to **CONDITIONAL** after a named waiver → Grimoire + runbook download → close on the graveyard, tombstones now glowing green | "Six gates give a verdict your change board can trust, with a runbook for the cutover window. Rest in peace, old firewall. NECROMANCER." |

Recording tips: 1080p, browser zoom at 110%, a clean browser profile, no other tabs or bookmarks visible. Record the voice separately and keep it short.
