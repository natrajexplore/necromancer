# Kiro Crew: "The Séance" multi-agent workflow

Target: **Best Kiro Crew App** bonus ($1k). Needs a Kiro Crew GitHub repo link from the **same GitHub account** as the submission.

## Idea
A persistent Crew that runs a migration ritual unattended across every config in `samples/dead-configs/`. It escalates to you only at approval gates.

```
            ┌─────────────── Séance Coordinator (Crew default agent) ───────────────┐
 config ──► │ ghoul-parser ─► autopsy-surgeon ─┬─► necromancer ─► oracle ─► gatekeeper │
            │                                  └── approval gate: accept tightening │
            │  heartbeat: re-run oracle nightly on main; alert on any divergence     │
            └────────────────────────────────────────────────────────────────────────┘
```

| Crew feature | How we use it |
|---|---|
| Subagents | The 5 custom agents in `.kiro/agents/` run as specialists |
| Approval gates | You approve each zero-trust tightening before the necromancer applies it, and each waiver before the gatekeeper issues a verdict |
| Workflows / Task Runner | One multi-step task per sample config, with checkpoints |
| Scheduling / heartbeat | Nightly job: `pytest -m pbt` with the `ci` profile on `main`. Alerts (Discord or Telegram) if Proof of Life fails |
| Artifacts | Each run saves the verdict, Grimoire report, runbook and the baseline (and tightened) PAN-OS configs into `crew/artifacts/<config>/` |
| Activity view | Screenshots of the plan, tool calls and gates go in the write-up and the video |

## Setup (verify against current docs at kiro.dev/docs/crew before running)
1. Install: see kiro.dev/docs/crew/installation. Open the dashboard (default `http://localhost:5476`).
2. Point Crew at this repository. Import or recreate the agents from `.kiro/agents/`.
3. Create the workflow "Séance" with the steps above. Add an approval gate before the tightening step.
4. Schedule the nightly Proof of Life heartbeat.
5. Run it once per sample config. Export the artifacts and screenshots into `crew/artifacts/`.
6. Record which parts were easier in Crew than in the IDE or CLI. This feeds the write-up section "IDE vs CLI vs Web vs Crew".

> Crew features and file formats change quickly (it's at v0.x). Configure everything through the Crew dashboard or docs, and commit the exported config here instead of hand-writing formats.
