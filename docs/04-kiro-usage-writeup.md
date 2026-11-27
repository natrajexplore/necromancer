# How we used Kiro

This write-up is built from [`kiro-journal.md`](kiro-journal.md) (42 entries, one per session, appended at the end of
each session by a Kiro hook), the git history, and the numbers in [`evidence.md`](evidence.md). Commit hashes can be
checked with `git show <hash>`. Where Kiro got something wrong, or the human had to step in, it says so.

Only Kiro CLI is claimed. Kiro Crew, Kiro Web, Powers and a vibe-coded comparison spike were planned in
[`03-build-plan.md`](03-build-plan.md) and were not done.

## 1. Spec-driven development

- Three specs in `.kiro/specs/`: `necro-engine`, `migration-governance` and `graveyard-ui`. Together they hold 126
  acceptance criteria in EARS form (73, 33 and 20). `check_repo.py` fails CI if a criterion has no task or a task cites
  a criterion that does not exist.
- 59 of the 66 task boxes are ticked (necro-engine 40 of 46, migration-governance 10 of 11, graveyard-ui 9 of 9). The
  open ones are Phase 2 work (ASA 8.3+, time-range schedule objects, hit counts, NAT rule emission, PDF and CSV export)
  and two optional stretch tasks.
- Each task was run in Kiro and committed with a `kiro-task: <spec>/<task>` trailer: 53 of the 91 commits at the time of
  measuring (`git log --grep="kiro-task" --oneline`).
- **Spec first, in practice.** When gating the tightened artifact turned out to be missing, the requirements
  (necro-engine 5.5 and 5.6, governance 1.8, 2.5, 4.8, 6.3 and 6.4) and the tasks were written first in the session, then
  the code. See `509b3a6` and the journal entry "necro-engine/7.1, migration-governance/11".
- **Work without a spec.** The AWS deployment (`bcf7bd7`, `42b5276`, `691099a`) and the secret-redaction leak fix
  (`1dc597c`) had no spec task. The journal marks them `none (vibe)`. In both cases the human gave the scope up front
  (no hard-coded account, region or e-mail address, no BOM, and each leaking form of the redaction).
- **Not done:** the planned comparison between a spec-driven parser and a vibe-coded one (the Check Point R65 spike).
  There are no comparison numbers, and none are claimed.

## 2. Steering

| File | Inclusion | What it holds |
|---|---|---|
| `product.md`, `tech.md`, `structure.md`, `security.md` | always | Product principles, stack and Windows workarounds, repository layout, data hygiene |
| `policy-semantics.md` | fileMatch (`backend/necro/**`, `backend/tests/**`, `samples/**`) | Exact ACL, NAT and zone semantics, name tables, the equivalence definition |
| `migration-governance.md` | fileMatch | Phases, gates G1 to G6, severity model, control mapping, report sections |
| `haunted-ui.md` | fileMatch | Palette, typography, motion, the metaphor map |
| `pbt-playbook.md` | manual | Properties P1 to P14 and the mutation suite |

**An example where the steering decided the outcome.** `policy-semantics.md` section 1.3 says ACLs do not filter
traffic to the device itself; management commands do. The first evaluator permitted every PIX and ASA flow to the
device's own addresses. Commit `e0fd0f3` ("model PIX/ASA traffic to the box with the management commands") fixed it
against that section, and the emitter now builds interface management profiles from the same functions.
Section 1.4 drove `ddc0999` (outbound ACL implicit deny).

## 3. Hooks

| Hook | Trigger | What it does |
|---|---|---|
| proof-of-life | PostFileSave on engine code | Runs the property-based tests (`pytest -m pbt -x`) |
| ghost-rule-guard | PostFileSave on samples and golden flows | Asks the agent to keep the `! GHOST:` annotations and the recall test in sync |
| readiness-gate-guard | PostFileSave on gates, report, runbook, validation | Runs the governance tests and restates the no-silent-GO rules |
| secret-exorcist | PreToolUse on writes | Asks the agent to confirm the content has no secrets, public IPs or real names |
| spec-traceability | PostFileSave on `requirements.md` | Asks for orphaned criteria and tasks |
| kiro-journal-on-stop | Stop | Appends one entry to `docs/kiro-journal.md` |

What the evidence shows: the journal hook wrote the 42 entries this document is built from, and the secret-exorcist
hook fired before file writes throughout the later sessions. We have no record of a secret that a hook stopped. The
redaction leaks that were fixed (`ef524bc`, `1dc597c`) were found by tests, by parsing a sample, and by review.

## 4. Custom agents

Five agents with scoped tools and prompts: `ghoul-parser`, `autopsy-surgeon`, `necromancer`, `oracle` and `gatekeeper`.
The `oracle` has no write access to production code by design.

Use was limited. The journal records the `gatekeeper` agent in two sessions (governance tasks 1 to 5 and 6 to 9). A request
to run the `oracle` agent could not be carried out from the running session, because `kiro-cli chat --agent oracle` is
interactive (journal, 2026-11-24). Most of the work ran in the default agent.

## 5. MCP

- **Own server.** `backend/mcp_server.py` (FastMCP over stdio) exposes `exhume`, `autopsy`, `resurrect`, `prove` and
  `gate`, and is registered in `.kiro/settings/mcp.json` (`3149f5a`). `backend/tests/test_mcp.py` starts it as a
  subprocess and calls the tools. Building it found a real bug: `git_commit()` let `git` inherit the protocol's stdin and
  hung the server (journal, governance 6 to 9).
- **Writes to `.kiro/settings/mcp.json` were denied** during the first attempt (journal, 2026-11-24), so the registration
  waited for a separate commit.
- **`fetch`** is configured. The journal has no entry that used it.
- The journal does not record Kiro calling the project's own tools while building the project, so there is no
  dogfooding claim.

## 6. Property-based testing

- 94 property-based tests, run at 5,000 examples each in the CI profile. 11 of the 14 playbook properties have tests.
  P4, P5 and P13 do not yet. Numbers: [`evidence.md`](evidence.md).
- The Proof of Life oracle is a product feature as well as a test tool. The mutation suite has 10 deliberate emitter bugs
  and the oracle must fail on each.
- **What PBT found.**
  - Hypothesis falsified a redaction property with the secret `"taca"`, a substring of `tacacs-server`. The redaction was
    correct and the test oracle was wrong (`bc02282`). The example is pinned.
  - The mutation suite exposed three gaps in the oracle itself. One was that rule coverage depended on the seed. The
    oracle now sweeps every witness flow before the random search (`c694716`).
  - Three emitter bugs were found by generated-policy equivalence checks while building the PAN-OS emitter (journal,
    tasks 6.1 to 6.6).
  - A Hypothesis deadline failed under the coverage tracer, and Kiro dropped the deadline for those tests.

## 7. Kiro surfaces

| Surface | Used | Notes |
|---|---|---|
| Kiro CLI | Yes, for everything | Specs, hooks, steering, custom agents and MCP all ran from it |
| Kiro IDE | Not claimed | TODO(owner): two journal entries are labelled `IDE` by the journal hook (2026-11-24 `necro-engine/7`, 2026-11-27 redaction fix). Confirm or relabel |
| Kiro Web | No | |
| Kiro Crew | No | [`crew/`](../crew/README.md) is a design |

**Friction we hit, from the journal and the history.**

- Kiro damaged spec files twice when ticking tasks: dropped characters (`631bf13`) and a broken encoding (`7d1f3a9`).
- The Kiro usage limit was reached once. One Kiro-authored test fix was formatted and committed outside Kiro (`bc02282`).
- Windows Smart App Control blocks unsigned executables. The fix was to use the signed python.org Python, set
  `UV_PYTHON_PREFERENCE=only-system` and run every tool as `python -m <tool>` (`d5bd5f2`).
- Two sessions ran at once and one found uncommitted files from the other. It stopped instead of overwriting them
  (journal, governance 1 to 5).

## 8. Where Kiro was corrected

| When | What happened | Fix |
|---|---|---|
| 2026-11-17 | Kiro dropped characters from the specs when ticking tasks 2.3 and 2.4 | `631bf13` |
| 2026-11-17 | A property test failed on the secret `"taca"`: the test, not the redaction, was wrong | `bc02282` |
| 2026-11-21 | An outbound ACL with no matching rule did not deny, and `decide()` swallowed exceptions, so P8 was not checked for real | `ddc0999` |
| 2026-11-24 | A Grimoire byte-identity test was flaky because it stamped the clock twice. The human reported the CI failure and required that the fix not weaken the comparison | `75d3faa` |
| 2026-11-24 | `tasks.md` encoding damaged in a previous commit | `7d1f3a9` |
| 2026-11-25 | `decide()` permitted every flow to the device's own addresses. The human specified the management-command semantics and gates | `e0fd0f3` |
| 2026-11-27 | The ledger recorded to-the-box flows whose decision did not change, which blocked G5 for no reason. The human overrode the Oracle-only scope | `5adf24d` |
| 2026-11-27 | The tightening work flagged `gate` and `grimoire` as out of scope for that task. The human then asked for a separate tightened verdict, with G6 judged on the tightened policy | `0a32260`, then `509b3a6` |
| 2026-11-27 | Secret-redaction leaks in several TACACS, RADIUS, AAA, username, isakmp, ftp and ppp forms. The human listed each leaking form | `1dc597c` |

## 9. Other tools and disclosure

- Claude (Anthropic) was used for the planning documents, the first drafts of the specs, steering, hooks and agents, the
  CI workflow, the repository-integrity script, code review, and fixes to the deploy script. 17 commits carry a
  `Co-Authored-By: Claude` trailer. All code under `backend/` and `frontend/` was generated in Kiro, with the one
  exception noted in section 7 (`bc02282`).
- Libraries: FastAPI, pydantic, Hypothesis, Mangum, the MCP Python SDK, React, Vite, Tailwind CSS, TanStack Query,
  Playwright and axe-core. The full lists are in `backend/pyproject.toml` and `frontend/package.json`.
