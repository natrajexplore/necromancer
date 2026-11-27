# Kiro Crew: "The Séance" (design, not built)

**Status: this is a design only. Nothing in this repository runs as a Kiro Crew.** There is no Crew workflow, no
exported Crew configuration, no schedule and no `crew/artifacts/` folder. NECROMANCER is not entered for a Kiro Crew
prize, and no part of the README or the Devpost text claims Crew use.

The folder is kept because the idea is a natural next step, and because it records what exists today that such a Crew
would build on.

## The idea

A persistent Crew that runs the migration ritual unattended across every config in `samples/dead-configs/`, and escalates
to a person only at approval gates.

```
            ┌─────────────── Séance Coordinator (Crew default agent) ───────────────┐
 config ──► │ ghoul-parser ─► autopsy-surgeon ─┬─► necromancer ─► oracle ─► gatekeeper │
            │                                  └── approval gate: accept tightening │
            │  heartbeat: re-run the oracle nightly on main; alert on any divergence │
            └────────────────────────────────────────────────────────────────────────┘
```

| Crew feature | How it would be used |
|---|---|
| Subagents | The five custom agents in `.kiro/agents/` as specialists |
| Approval gates | A person approves each tightening before it is applied, and each waiver before a verdict is issued |
| Workflows | One multi-step task per sample config, with checkpoints |
| Scheduling | A nightly `pytest -m pbt` run at the `ci` profile on `main`, with an alert when Proof of Life fails |
| Artifacts | The verdict, report, runbook and the baseline and tightened PAN-OS configs per config |

## What exists today

- The five agent definitions and prompts in `.kiro/agents/`. The journal records one of them (`gatekeeper`) in use.
- The engine operations a Crew would call, through the CLI (`python -m necro ...`), the API and the MCP server.
- The approval steps as data: the tightening selection (`--tightening FILE`) and the sidecar with ledger decisions
  (`--sidecar FILE`).
- A related check in CI: the `ci.yml` workflow runs the property-based tests on every push and pull request. It is not a
  nightly schedule and it is not a Crew.

## What would have to be built

1. Install Kiro Crew and import or recreate the five agents.
2. Create the workflow with an approval gate before the tightening step.
3. Schedule the nightly Proof of Life run and an alert channel.
4. Run it once per sample config and keep the exported configuration and artifacts here.

Kiro Crew is a young product and its formats change. Check the current Kiro documentation before building it, and commit
the exported configuration rather than writing a format by hand.
