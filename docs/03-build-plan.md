# 25-Day Build Plan (Nov 10 → Dec 4)

Rule of thumb: **Kiro writes the code, you steer.** Each task in `.kiro/specs/*/tasks.md` is run in Kiro (IDE "Start task", or CLI / Crew), then committed with a `kiro-task: <id>` trailer. That builds the evidence trail for the "Technological Implementation" score.

| Dates (IST) | Milestone | Kiro surface | Exit criteria |
|---|---|---|---|
| **Nov 10–11** | Request credits. Create the GitHub repo + MIT license. Push this scaffold. Attend the Build Session (Nov 11, 11:30 PM IST) | — | Repo public, `.kiro` visible, credits requested |
| Nov 12 | Review and refine the specs **inside Kiro** (ask Kiro to critique requirements.md and design.md, and accept its edits). Check the golden flows against vendor docs | IDE | Specs approved in Kiro |
| Nov 13–16 | necro-engine tasks 1–4: IR, PIX/ASA parser, IOS parser, evaluator | IDE (spec tasks) | Parser PBT round-trip passes |
| Nov 17–19 | Tasks 5–7: autopsy, PAN-OS emitter, tightening + ledger | CLI + custom agents | Autopsy finds every seeded ghost rule in the samples |
| Nov 20–22 | Task 8: **Proof of Life oracle** (Hypothesis) | IDE + `oracle` agent | `0 divergences / 10k` on samples, plus a shrunk counterexample on a deliberately broken emitter |
| Nov 23 | Task 9: custom MCP server. Wire it into `.kiro/settings/mcp.json` | CLI | Kiro chat can call `@necromancer/prove` |
| Nov 23–24 | migration-governance tasks 1–9: gates G1–G6, verdict, audit header, Grimoire, runbook, `necro gate` | IDE + `gatekeeper` agent | Every sample gives the expected verdict, and all 55 golden flows pass |
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
