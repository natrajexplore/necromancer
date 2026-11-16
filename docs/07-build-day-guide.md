# Build-day guide: from specs to a demo-ready app in Kiro

Goal: finish everything planned up to the Nov 30 feature freeze in one long Kiro session, then record the video on
another day. **Kiro writes all application code.** You start tasks, review, test and commit.

Twelve planned days in one day is only realistic with Kiro in **Autopilot** and a strict order. Work top-down. Each batch
has a checkpoint; don't start the next batch until the checkpoint passes. If time runs out, stop after a checkpoint. The
minimum demo is batches 1–8.

---

## 0. Setup (≈ 30 min)

| Step | How |
|---|---|
| Install Kiro | Download from https://kiro.dev, install, sign in |
| Request credits | Kiroween credit form (see `docs/01-rules-analysis.md`), if not done yet |
| Open the project | Kiro → Open Folder → `D:\Gen AI Program\necromancer_kiro` |
| Python 3.12 | `uv python install 3.12` (uv is installed; your system Python is 3.15, the project pins 3.12) |
| Node | Installed (v26 locally; CI uses 22 — fine) |
| Check the scaffold | `python -I .github/scripts/check_repo.py` → all `ok` |

In Kiro:
1. Open the **Kiro panel**. Confirm it sees the 3 specs, 8 steering docs, 6 hooks and the agents.
2. Switch the chat to **Autopilot** so Kiro can edit files and run commands without asking each time. Allow the
   commands it needs (`uv`, `pytest`, `ruff`, `mypy`, `npm`, `git`).
3. The `necromancer` MCP server is **disabled** until task 9.3 builds it. Leave `fetch` enabled.
4. The `proof-of-life` hook runs pytest on save. It fails until task 1 creates `backend/`. Ignore that until then.

Evidence for judging (keep doing this all day): screenshot the first hook firing, the first spec task completing, the
first PBT counterexample, the first MCP call, and keep `docs/kiro-journal.md` updated (the Stop hook does most of it).

---

## Prompt template

Paste into Kiro chat for each batch, replacing the spec and task numbers:

```
Execute tasks <A>–<B> of .kiro/specs/<spec>/tasks.md in order, following the steering docs.
For each task:
1. Implement it, including its tests.
2. From backend/, run: uv run ruff check . ; uv run mypy --strict necro ; uv run pytest -q
   and fix until green.
3. Tick the task's checkbox in tasks.md.
4. git commit with a conventional message and the trailer "kiro-task: <spec>/<task id>".
Rules: never edit samples/golden-flows/* or samples/dead-configs/* to make a test pass, never lower
coverage or Hypothesis budgets, never drop or widen behaviour silently. If a golden flow fails and you
believe the expectation is wrong, stop and explain why, citing policy-semantics.md.
```

You can also open `tasks.md` and use **Start task** above each task. Batching through chat is faster today.

---

## The batches

| # | Spec · tasks | What you get | Checkpoint (must pass before moving on) | Est. |
|---|---|---|---|---|
| 1 | necro-engine · **1** | `backend/` skeleton, pyproject, conftest, Hypothesis profiles | `cd backend; uv run pytest -q` runs. `git push` → CI **backend** job runs and is green | 30 m |
| 2 | necro-engine · **2–3** | IR, sets, masks, names, redaction, evaluator, zones, NAT model | `uv run pytest -q -m pbt` green (P8, P9) | 1.5 h |
| 3 | necro-engine · **4** | PIX/ASA ≤ 8.2 + IOS parsers, detection, coverage, golden-flow test (source side) | `uv run pytest -q tests/test_golden_flows.py` green for PIX, ASA 8.2, IOS | 1.5 h |
| 4 | necro-engine · **5–6** | Autopsy, PAN-OS emitter + reader | Autopsy recall test = 100% on seeded `! GHOST:` lines | 1.5 h |
| 5 | necro-engine · **7–8** | Ledger, **Proof of Life** oracle | `HYPOTHESIS_PROFILE=ci uv run pytest -q -m pbt` green; haunted-emitter test produces a shrunk counterexample | 1.5 h |
| 6 | necro-engine · **9** (do 9.2–9.4; 9.1 comes with batch 7) | API, MCP server, `necro` CLI | `uv run necro prove ../samples/dead-configs/pix-2006-hq.cfg --profile ci` reports 0 divergences. Set `"disabled": false` for `necromancer` in `.kiro/settings/mcp.json` and call it from Kiro chat (screenshot) | 1 h |
| 7 | migration-governance · **1–9** | Gates, verdict, audit header, Grimoire, runbook, `necro gate` | `uv run necro gate ../samples/dead-configs/pix-2006-hq.cfg` prints a verdict with blocking reasons | 2 h |
| 8 | graveyard-ui · **1–7** | Haunted UI: graveyard → autopsy → resurrect → proof → verdict + Grimoire | `npm --prefix frontend run dev` + backend running: the full ritual works on `pix-2006-hq` in the browser | 2.5 h |
| 9 | Deploy | S3 + CloudFront UI, FastAPI on Lambda, $1 budget alarm | Public URL works in an incognito window | 1.5 h |
| 10 | Optional | graveyard-ui 8–9, Kiro Crew Séance run, vibe-coding spike | Screenshots | — |

Skip all **[P2]** tasks (necro-engine 10+, governance 10). ASA 9.8 isn't needed for the demo.

**Deploy (batch 9) needs:** an AWS account, the AWS CLI (not installed yet: `winget install Amazon.AWSCLI`, then
`aws configure`), and a budget alarm. If today runs long, deploy tomorrow morning before recording. The video can show
the app running locally; the **live URL** is required for the submission, not for the video.

---

## How to run the app (once batches 1–8 are done)

Backend (terminal 1):
```powershell
cd "D:\Gen AI Program\necromancer_kiro\backend"
uv sync
uv run pytest -q                                   # all tests (dev profile)
uv run necro prove ..\samples\dead-configs\pix-2006-hq.cfg --profile demo
uv run necro gate  ..\samples\dead-configs\pix-2006-hq.cfg
uv run uvicorn necro.api:app --reload --port 8000  # API at http://localhost:8000/healthz
```
(Kiro may choose a different module path for the API; use what task 9.2 created.)

Frontend (terminal 2):
```powershell
cd "D:\Gen AI Program\necromancer_kiro"
npm --prefix frontend install
npm --prefix frontend run dev                      # open the URL Vite prints, usually http://localhost:5173
```

Demo walkthrough (matches `docs/05-demo-video-script.md`): open the PIX tombstone → autopsy ghosts → Resurrect →
Prove (0 divergences) → toggle **Haunt it** (counterexample card) → verdict → download the Grimoire.

---

## If something goes wrong

| Symptom | Do this |
|---|---|
| A golden flow fails | Paste the failure into Kiro and ask it to fix the **code**. If Kiro argues the expectation is wrong, stop and ask me to check it against the semantics |
| Kiro wants to lower coverage or budgets | Refuse. Ask it to add tests instead |
| CI red after push | Open the failed job, paste the log into Kiro |
| Kiro drifts from the spec | Point it at the task's `_Requirements:` lines and the steering doc |
| Out of credits | Request credits; continue with the remaining free allowance on the smallest batches first |

After each batch: `git push`, check CI, and tell me. I'll review the output against the specs and golden flows.
