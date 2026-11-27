# Demo video script

Target length 2:50. Hard limit 3:00.

Rules for the recording: public YouTube, the real app running, **no copyrighted music** (self-made or royalty-free
with a licence you hold), **no vendor logos**. Vendor and product names appear only as the plain text the app shows.

Record against the live demo, `https://7bs6otuwci.execute-api.ap-southeast-2.amazonaws.com`, or locally (see the README
quick start). Everything below uses the bundled sample `pix-2006-hq` and only synthetic data. The labels in bold are the
exact button and heading texts in the app.

## Before recording

- Open the page once and click through to **Run the gates** so the Lambda is warm. The first request after a quiet period
  includes a cold start.
- Use a clean browser profile at 1080p, zoom 110%, no other tabs or bookmarks visible.
- Under reduced motion the rise animation is skipped. Leave the system setting off so the 2.4 second rise plays.
- The gates take about 13 seconds on the live demo. Cut that wait in the edit and keep the "Running the gates" line on screen for a second.
- Record the voice-over separately and keep it short.

## Script

| Time | On screen | Voice-over |
|---|---|---|
| 0:00 to 0:12 | The graveyard: four tombstones in order, `pix-2006-hq` (Cisco PIX, died 2013), `asa-8.2-branch` (2016), `ios-12-edge` (2016), `asa-9.8-dc` (2024). The privacy note is visible | "Every enterprise has a graveyard: firewalls that died years ago and still guard production, because nobody can prove a rewrite of thousands of rules behaves the same." |
| 0:12 to 0:27 | Click the `pix-2006-hq` tombstone. Step 1, **Exhume**: Cisco PIX 6.3(5), detection confidence 0.95, coverage 100% | "NECROMANCER exhumes the config. Secrets are redacted first, and every line is accounted for. Here, all 41 security-relevant lines are handled." |
| 0:27 to 0:45 | Step 2, **Autopsy**: 21 findings. Click a shadowed rule and the rule that shadows it lights up. Stop on `AUT-0008`, the critical **Cursed Port**, "insecure service, critical" on `outside_in#5` | "Autopsy finds ghost rules: shadowed, redundant, too broad. And this one is critical: telnet allowed from an outside network to the web server." |
| 0:45 to 1:10 | Step 3, click **Resurrect**: the rise plays, then the original beside the PAN-OS candidate. Under "Zero-trust tightening" click **Accept AUT-0008**, type an approver name, click **Prove the tightened artifact**. The summary says the proof passed, and the tightened ledger shows `TGT-0001` | "Resurrection gives a like-for-like PAN-OS candidate. Tightening is a separate change: I accept one fix as a named person, and it gets its own config, its own ledger entry and its own proof. The baseline is untouched." |
| 1:10 to 1:25 | Step 4, **Proof of Life**, click **Prove**. The heartbeat draws. Stats: 1,899 generated flows, 0 divergences, golden flows 16 of 16 passed. The per-context table shows `outside:in`, `inside:in` and `dmz:in` passed | "Then the proof. A property-based oracle checks thousands of boundary-biased packets, and sixteen hand-verified golden flows, against the re-parsed PAN-OS config." |
| 1:25 to 1:50 | Tick **Haunt it**, click **Prove**. The heartbeat goes flat. The card **The packet that refused to rest**: `tcp 203.0.113.7:40000 -> 192.168.50.10:80`, golden flow PIX-01, the original permits it through `outside_in#1`, the candidate denies it. The "Haunted" notice is visible | "Break the emitter on purpose and the oracle catches it. It shows the exact packet that refused to rest, with both decisions. This switch is a demo: gate and grimoire refuse a haunted candidate." |
| 1:50 to 2:30 | Step 5, **Verdict**, click **Run the gates**. The badge reads **NO-GO** for the baseline artifact. Blocking reasons: G5 `LED-0001` pending, G6 critical finding `AUT-0008`. Click **tightened (1 accepted)**. Under "Pending ledger entries (tightened artifact)" type the approver name and the reason, click **Accept LED-0001**, click **Run the gates again**. The badge turns **GO** "for the tightened artifact (separate change)". The line "Baseline: NO-GO. Tightened (separate change): GO." is visible | "Six gates give the verdict, with the blocking reasons first. The baseline is NO-GO: a ledger entry is still pending and a critical finding is open. Judge the tightened artifact, record a named approver and a reason for the ledger entry, run the gates again, and it is GO. The baseline verdict never changed." |
| 2:30 to 2:42 | Click **Download report (Markdown)** and scroll the report: both verdicts, the ledger with the approver and reason, the runbook. Quick cut to the repository: `.kiro/specs` with ticked tasks, a hook entry, the `docs/evidence.md` table | "The Grimoire carries both verdicts, the ledger and the cutover runbook. Built spec-first in Kiro CLI: three specs, hooks, steering, and an MCP server. Every number is in docs slash evidence." |
| 2:42 to 2:50 | The graveyard. The live demo URL on screen | "Rest in peace, old firewall. NECROMANCER." |

## Notes for the edit

- Keep the NO-GO to GO sequence at normal speed. It is the point of the video.
- Do not show or say "compliant" or "safe to deploy". The product never does.
- The numbers on screen (21 findings, 1,899 flows, 16 of 16, `AUT-0008`, `LED-0001`) are what the app shows for this
  sample today. If the sample or the engine changes, re-run the walkthrough and update the script.
- The deployed build can lag the repository (check `/healthz`). Record from the same build you describe.
