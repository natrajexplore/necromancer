# How we used Kiro (write-up template, fill from docs/kiro-journal.md)

> Judges score depth and variety. Every claim here should point to a file, commit or screenshot. Be honest: say where Kiro struggled and what you corrected.

## 1. Spec-driven development vs vibe coding
- Three specs: `necro-engine` (Phase 1 MVP + Phase 2 enterprise tasks, ~80 acceptance criteria in EARS format), `migration-governance` (gates, verdict, report, runbook) and `graveyard-ui`.
- Workflow: requirements → design → tasks, each task run in Kiro and committed with a `kiro-task:` trailer (`git log --grep kiro-task | wc -l` = __).
- **Controlled comparison:** the Check Point R65 parser was vibe-coded first (task 11). Results: __ bugs found by the oracle vs __ for the spec-driven ASA parser. Time taken: __ vs __. Lesson: __.

## 2. Steering docs (3 inclusion modes)
| File | Mode | Why |
|---|---|---|
| product.md, tech.md, structure.md, security.md | always | Shared context and data-hygiene rules |
| policy-semantics.md | fileMatch `backend/necro/**`, `samples/**` | Exact ACL, NAT and zone semantics only load when touching the engine or fixtures |
| migration-governance.md | fileMatch gates/report/runbook | Mandatory phases, gates and control mapping only load for governance work |
| haunted-ui.md | fileMatch `frontend/**` | Design tokens only for UI work |
| pbt-playbook.md | manual (`#pbt-playbook`) | Loaded on demand when writing properties |
Example where steering prevented a bug: __ (e.g. subnet vs wildcard mask).

## 3. Agent hooks (v1 JSON, `.kiro/hooks/`)
| Hook | Trigger | Automates |
|---|---|---|
| proof-of-life | PostFileSave (engine files) | Runs PBT on every save |
| ghost-rule-guard | PostFileSave (sample configs, golden flows) | Keeps seeded ghosts, golden flows and the recall test in sync |
| readiness-gate-guard | PostFileSave (gates/report/runbook) | Runs governance tests and re-checks the no-silent-GO rules |
| secret-exorcist | PreToolUse (write) | Blocks secrets and real IPs before writes |
| spec-traceability | PostFileSave (requirements.md) | Finds orphaned criteria and tasks |
| kiro-journal-on-stop | Stop | Logs evidence for this write-up |
Best catch by a hook: __.

## 4. Custom agents
`ghoul-parser`, `autopsy-surgeon`, `necromancer`, `oracle`, `gatekeeper`. Each has scoped tools and file areas. The **oracle can't edit production code**, which keeps the verifier independent of the code it verifies.

## 5. MCP integrations
- **Custom MCP server** (`backend/mcp_server.py`) exposing `exhume`, `autopsy`, `resurrect`, `prove`. Kiro used our own product as a tool while building it (dogfooding). Example: __.
- `fetch` MCP for reading vendor docs during the parser work.

## 6. Property-based testing
Properties P1–P14 (`.kiro/steering/pbt-playbook.md`), plus 55 hand-verified golden flows that are independent of the evaluator. Headline: the **Proof of Life oracle** is PBT used *as a product feature*, not only for tests. The mutation sanity suite (10 mutants, incl. swapped `lt`/`gt`, an untranslated 8.3+ NAT destination and ICMP widened to `ping`) shows it catches each one with a shrunk counterexample: `__`.

## 7. Kiro surfaces: IDE vs CLI vs Web vs Crew
| Surface | Used for | Strength | Friction |
|---|---|---|---|
| IDE | Spec tasks, UI | __ | __ |
| CLI | Custom agents, deploy scripts, MCP testing | __ | __ |
| Web | Vibe spike (task 11) | __ | __ |
| Crew | Séance workflow, nightly heartbeat | __ | __ |

## 8. Powers and third-party tools
- Kiro Powers used: __ (and/or the packaged `necromancer` power, if built).
- Other tools, disclosed: planning documents for this repo were drafted with Claude before implementation started. All application code was generated and iterated in Kiro.
- Libraries: FastAPI, pydantic, Hypothesis, React, Vite, Tailwind, Framer Motion (all OSS).
