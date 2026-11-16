# 25-Day Build Plan (Nov 10 → Dec 4)

Rule of thumb: **Kiro writes the code, you steer.** Each task in `.kiro/specs/*/tasks.md` is run in Kiro (IDE "Start task", or CLI / Crew), then committed with a `kiro-task: <id>` trailer. That builds the evidence trail for the "Technological Implementation" score.

## Re-baselined plan (Nov 16)
No application code existed on Nov 16, so the original plan below was 4 days behind. This schedule replaces it.
The internal submission date (Dec 3) does not move.

| Dates (IST) | Milestone | Exit criteria |
|---|---|---|
| **Nov 16** | Specs review in Kiro (1 hour max), then necro-engine **task 1** (skeleton) | CI backend job switches on and passes |
| Nov 17–18 | Tasks **2–3**: IR, normalized sets, evaluator, zones, NAT model | PBT P9 passes. Source side of the PIX/ASA 8.2/IOS golden flows passes |
| Nov 19–20 | Task **4**: parsers (PIX/ASA ≤ 8.2, IOS), coverage | Every sample parses. Unparsed lines reported. Parser round-trip PBT passes |
| Nov 21 | Tasks **5–6**: autopsy, PAN-OS emitter + reader | Autopsy recall = 100% on seeded ghosts |
| Nov 22 | Tasks **7–8**: ledger, **Proof of Life** | `0 divergences` at `ci` on PIX/ASA 8.2/IOS, plus a shrunk counterexample from the haunted emitter |
| Nov 23 | Task **9**: CLI, API, MCP server | `necro prove` works. Kiro chat calls the MCP `prove` tool |
| Nov 24–25 | migration-governance tasks **1–9** | `necro gate` gives the expected verdict on every P1 sample |
| Nov 26–28 | graveyard-ui tasks **1–7** (8–9 if time allows) | Full ritual on `pix-2006-hq` in the browser |
| Nov 29 | Deploy (S3 + CloudFront, Lambda), $1 budget alarm | Public URL works in an incognito window |
| Nov 30 | **Feature freeze.** Kiro Crew Séance run + screenshots. Startup one-pager | Crew evidence captured |
| Dec 1 | Record the demo video (< 3:00), upload as public | Video live |
| Dec 2 | Write-up, Devpost text, blog post, social post | All drafts final |
| **Dec 3** | **Submit on Devpost** | Submitted ✅ |
| Dec 4 | Buffer only | — |

**Cut list, in order, if a milestone slips by more than a day:**
1. The vibe-coding spike (write-up uses spec-vs-vibe reasoning without a build).
2. Zero-trust tightening in the UI (keep the ledger in the API/report).
3. graveyard-ui tasks 8–9 (accessibility pass, Playwright) beyond a basic keyboard check.
4. Kiro Crew bonus.
5. HTML report (keep Markdown).

**Never cut:** Proof of Life with a shrunk counterexample, the verdict, a working public URL, the video. They are the demo.

**Minimum demo path:** PIX 6.3 sample → autopsy → resurrect → prove (0 divergences, then "Haunt it" counterexample) →
verdict → Grimoire download. ASA 9.8 (Phase 2) is not needed for the demo.

## Original plan (Nov 10, superseded)

| Dates (IST) | Milestone | Kiro surface | Exit criteria |
|---|---|---|---|
| **Nov 10–11** | Request credits. Create the GitHub repo + MIT license. Push this scaffold. Attend the Build Session (Nov 11, 11:30 PM IST) | — | Repo public, `.kiro` visible, credits requested |
| Nov 12 | Review and refine the specs **inside Kiro** (ask Kiro to critique requirements.md and design.md, and accept its edits). Check the golden flows against vendor docs | IDE | Specs approved in Kiro |
| Nov 13–16 | necro-engine tasks 1–4: IR, PIX/ASA parser, IOS parser, evaluator | IDE (spec tasks) | Parser PBT round-trip passes |
| Nov 17–19 | Tasks 5–7: autopsy, PAN-OS emitter, tightening + ledger | CLI + custom agents | Autopsy finds every seeded ghost rule in the samples |
| Nov 20–22 | Task 8: **Proof of Life oracle** (Hypothesis) | IDE + `oracle` agent | `0 divergences / 10k` on samples, plus a shrunk counterexample on a deliberately broken emitter |
| Nov 23 | Task 9: custom MCP server. Wire it into `.kiro/settings/mcp.json` | CLI | Kiro chat can call `@necromancer/prove` |
| Nov 23–24 | migration-governance tasks 1–9: gates G1–G6, verdict, audit header, Grimoire, runbook, `necro gate` | IDE + `gatekeeper` agent | Every sample gives the expected verdict, and all 58 golden flows pass |
| Nov 24 | **Vibe-coding spike**: build a Check Point parser stub *without* a spec, then compare (for the write-up) | Web | Comparison notes written |
| Nov 24–27 | graveyard-ui spec tasks: graveyard, autopsy, resurrection animation, proof viewer, report | IDE | Full end-to-end flow in the browser |
| Nov 27 | **Kiro Crew**: run the multi-agent "Séance" workflow (see `crew/README.md`) on all samples, with screenshots | Crew | Crew repo link ready |
| Nov 28–29 | Deploy: S3 + CloudFront static UI, FastAPI on Lambda (Mangum), $1 budget alarm | CLI | Public URL works in incognito |
| Nov 30 | **Feature freeze.** Startup one-page website. LinkedIn founder line | — | — |
| Dec 1 | Record the demo video (<3:00) and upload to YouTube as public | — | Video live |
| Dec 2 | Kiro usage write-up, Devpost text, blog post, social post | — | All drafts final |
| **Dec 3** | **Submit on Devpost** (a day early). Check the repo About shows the license | — | Submitted ✅ |
| Dec 4 | Buffer only. Don't start new features | — | — |

## Scope guard
Only **[P1]** tasks are in the hackathon scope. **[P2]** tasks (ASA 8.3+ object NAT, NAT rule emission, PDF/CSV export) start only after Nov 30 if time remains, and are never needed for the demo.

## Daily hygiene
- Commit small. Message format: `feat(parser): ASA object-group nesting\n\nkiro-task: necro-engine/2.3`
- Each evening, add 3 lines to `docs/kiro-journal.md` (created by the Stop hook): what Kiro did, what you corrected, which surface you used. This becomes the write-up.
- Screenshot every "first time" moment: first hook firing, first MCP call, first Crew run, first PBT counterexample.
