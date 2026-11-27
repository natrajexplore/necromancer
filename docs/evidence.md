# Evidence

Every number in the README and the Devpost text comes from a command in this file. Each row shows the
command as it was run and what it printed.

- **Measured on:** 2026-11-27, at commit `7eb6f08` (the commit that was checked out when the commands ran).
  Counts that depend on git history (commits, `kiro-task` commits) grow as commits are added.
- **Machine:** Windows 11 (10.0.26300), Python 3.12.10, uv 0.13.7, Node v26.13.0, npm 11.20.0, Playwright 1.65.1,
  Google Chrome (for Lighthouse).
- **Shell:** Windows PowerShell. On Linux, replace `$env:NAME='x'` with `NAME=x` and `..\` with `../`.
- **Timings** are wall-clock on that machine and will differ on yours. Counts and scores are deterministic, except
  where a row says otherwise.
- **Not measured here:** the GitHub Actions results. The CI badge in the README shows the latest run.

Backend commands run from `backend/` with `$env:UV_PYTHON_PREFERENCE='only-system'` (see the Windows note in
`.kiro/steering/tech.md`). Frontend commands run from `frontend/`.

## Backend

| What | Command | Result |
|---|---|---|
| Lint | `uv run ruff check .` | All checks passed |
| Format | `uv run ruff format --check .` | 154 files already formatted |
| Types | `uv run mypy --strict necro` | Success: no issues found in 82 source files |
| Tests and coverage | `$env:HYPOTHESIS_PROFILE='dev'; uv run pytest -q -m "not perf" --cov=necro --cov-report=term --cov-fail-under=90` | **2240 passed**, 1 skipped, 6 deselected, in 12 min 6 s. Coverage of `necro/`: **98.63%** (8,189 statements, 112 missed) |
| Performance checks | `uv run pytest -q -m perf` | 6 passed in 46 s |
| Dependency audit | `uv run pip-audit` | No known vulnerabilities found (the local package `necromancer` is skipped because it is not on PyPI) |

The one skipped test is `test_golden_flows_asa_9_8` (`backend/tests/test_golden_flows.py`, line 199). Its skip
reason is `Phase 2: ASA 8.3+ object NAT, global ACL and any4 (task 1.13)`.

## Property-based tests

| What | Command | Result |
|---|---|---|
| Hypothesis budgets | `Select-String -Path backend\tests\conftest.py -Pattern "max_examples"` | `dev` 500, `ci` 5,000, `demo` 10,000 examples |
| Number of PBT tests | `uv run pytest -m pbt --collect-only -q` | 94/2247 tests collected (2153 deselected) |
| PBT at the CI budget | `$env:HYPOTHESIS_PROFILE='ci'; uv run --with pytest-xdist==3.6.1 pytest -q -m pbt -n auto` | **94 passed** in 8 min 38 s (5,000 examples per property) |
| Which playbook properties have a test | `Select-String -Path backend\tests\test_*.py -Pattern '\bP(1[0-4]\|[1-9])\b'`, read against `.kiro/steering/pbt-playbook.md` | P1, P2, P3, P6, P7, P8, P9, P10, P11, P12 and P14 have tests (**11 of 14**). P4 (reorder disjoint rules), P5 (object-group expansion is idempotent) and P13 (ASA 8.3+ NAT mapping, Phase 2) have no property test yet |

## Golden flows and the mutation suite

| What | Command | Result |
|---|---|---|
| Hand-verified flows per file | `foreach($f in Get-ChildItem samples\golden-flows\*.toml){ "{0} {1}" -f $f.Name,(Select-String -Path $f.FullName -Pattern '^\[\[flow\]\]').Count }` | asa-8.2-branch 13, asa-9.8-dc 16, ios-12-edge 13, pix-2006-hq 16: **58 flows** |
| Golden flows against the evaluator | `uv run pytest -q tests/test_golden_flows.py tests/test_sample_golden.py -rs` | 102 passed, 1 skipped. **42 flows are active** (PIX, ASA 8.2, IOS). **16 flows are Phase 2 and skipped** (asa-9.8-dc) |
| Number of mutants | `uv run python -c "from tests.mutants import MUTANTS; print(len(MUTANTS))"` | **10** |
| Mutants caught | `uv run pytest -q tests/test_oracle_mutants.py` | 27 passed. Each mutant must make the proof fail with a counterexample |
| Proof of Life on a sample | `uv run python -m necro prove ..\samples\dead-configs\pix-2006-hq.cfg --profile demo --format text` | PASS. 30,712 flows checked in 3 contexts (10,000 requested per context; the contexts ran 10,333, 10,135 and 10,244). Golden flows 16 of 16. 1 ledger entry. Seed 1313162066. 5.0 s |

The ten mutants are: `lt` and `gt` swapped, range upper bound off by one, `neq` emitted as `eq`, subnet mask
emitted as wildcard, rule order reversed for two overlapping rules, final deny dropped, inactive rule emitted as
enabled, ICMP echo-reply widened to the `ping` App-ID, 8.3+ real destination left untranslated, and to-zone forced
to `any` (`backend/tests/mutants.py`).

## The pix-2006-hq sample

| What | Command | Result |
|---|---|---|
| Exhume | `uv run python -m necro exhume ..\samples\dead-configs\pix-2006-hq.cfg --format text` | pix 6.3(5), detection confidence **0.95**, 59 lines, 41 security-relevant lines, 41 handled, 0 blocking |
| Autopsy | `uv run python -m necro autopsy ..\samples\dead-configs\pix-2006-hq.cfg --format text` | 21 findings: 1 critical, 3 high, 5 medium, 12 low. AUT-0008 is the critical one (insecure service, `outside_in#5`) |
| Verdict, baseline and tightened | the live check below, and `frontend/e2e/ritual.spec.ts` | Baseline NO-GO (G5: LED-0001 pending, G6: AUT-0008). Tightened GO with AUT-0008 and LED-0001 accepted |
| Seeded ghosts and recall | `(Select-String -Path samples\dead-configs\*.cfg -Pattern "^! GHOST:").Count`, then `uv run pytest -q tests/test_autopsy_recall.py` | 21 seeded `! GHOST:` rules (pix 7, asa-8.2 3, ios 5, asa-9.8 6). The recall test requires 100% and passes (6 passed) |
| Sample counts | `(Get-ChildItem samples\dead-configs -File).Count; (Get-ChildItem samples\broken-configs -File).Count` | 4 dead configs, 4 broken-config fixtures |
| ASA 9.8 is Phase 2 | `uv run python -m necro gate ..\samples\dead-configs\asa-9.8-dc.cfg --budget 40` | NO-GO. `G1: asa 9.8(4) is not in the supported list (PIX 6.x, ASA 7.0-8.2, IOS 12.x)` |

## Frontend

| What | Command | Result |
|---|---|---|
| Types | `npx.cmd tsc --noEmit -p .` | no errors |
| Unit tests | `npm.cmd test` | 12 files, **124 tests passed** |
| Production build | `npm.cmd run build` | built |
| Dependency audit | `npm.cmd audit --audit-level=high` | found 0 vulnerabilities |
| End to end | `npm.cmd run e2e` | **9 passed** in 39 s: 3 axe tests, 4 keyboard and reduced-motion tests, 2 ritual tests (full ritual, haunted path) |
| Lighthouse | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\lighthouse.ps1` | Desktop preset, Lighthouse 13.6.0: performance **100**, accessibility **100**, best practices **100**, SEO **100** |

The e2e tests start the real engine and the Vite dev server (`frontend/playwright.config.ts`). axe runs with no rule
disabled and fails on any serious or critical violation. Details are in [a11y-lighthouse.md](a11y-lighthouse.md).

## Specs, steering and Kiro artifacts

| What | Command | Result |
|---|---|---|
| Acceptance criteria per spec | `foreach($s in 'necro-engine','migration-governance','graveyard-ui'){ "$s " + (Get-Content ".kiro/specs/$s/requirements.md" \| Select-String '^\d+\.\d+\s').Count }` | necro-engine 73, migration-governance 33, graveyard-ui 20: **126** |
| Task boxes ticked per spec | `(Get-Content ".kiro/specs/$s/tasks.md" \| Select-String '^\s*- \[x\]').Count` for each spec | necro-engine 40 ticked, 6 open (Phase 2 tasks 10 to 13 and the two optional stretch tasks 14 and 15); migration-governance 10 ticked, 1 open (task 10, PDF and CSV export, Phase 2); graveyard-ui 9 ticked, 0 open |
| Spec traceability | `python -I .github/scripts/check_repo.py` | every check ok: `.kiro` JSON, `.kiro` not ignored, spec traceability, sample annotations, synthetic IPs, 58 golden flows in 4 files |
| Commits with a `kiro-task` trailer | `git log --grep="kiro-task" --oneline \| Measure-Object` | **53** of 91 commits |
| Steering, hooks, agents | `(Get-ChildItem .kiro\steering).Count; (Get-ChildItem .kiro\hooks).Count; (Get-ChildItem .kiro\agents -Filter *.json).Count` | 8 steering docs, 6 hooks, 5 custom agents |
| MCP tools | `.kiro/settings/mcp.json` and `backend/necro/mcp_tools.py` | `necromancer` server with 5 tools (`exhume`, `autopsy`, `resurrect`, `prove`, `gate`), plus `fetch` |
| CI jobs | `Select-String -Path .github\workflows\ci.yml -Pattern '^  [a-z-]+:$'` | 4 jobs: `repo-integrity`, `backend`, `frontend`, `e2e` |
| Commits with a Claude co-author trailer | `git log --grep="Co-Authored-By: Claude" --oneline \| Measure-Object` | **17**. Only one of them, `bc02282`, touches `backend/` or `frontend/` (a test file, formatted and committed outside Kiro after the usage limit, as its message says) |
| First commit | `git log --reverse --format=%ad --date=short \| Select-Object -First 1` | 2026-11-10 |
| Documentation hygiene | `python -I .github/scripts/check_docs.py` | 0 problems: UTF-8 without BOM, no mojibake, no e-mail addresses, links and anchors resolve, one H1 per file, no skipped heading levels |

Two more documentation checks were done by hand and are not part of `check_docs.py`:

| What | Command | Result |
|---|---|---|
| The README's two Mermaid diagrams render | each block saved to a `.mmd` file, then `npx.cmd -y @mermaid-js/mermaid-cli@11 -i d1.mmd -o d1.svg -p pp.json`, with `pp.json` pointing Puppeteer at the installed Chrome | both diagrams rendered to SVG with no parse error |
| External links | `Invoke-WebRequest <url> -Method Head` for each `https` link in the README and `docs/` | 200 for the repository, the CI badge and workflow, the security advisories page, the badges, `docs.astral.sh/uv`, `kiro.dev` and the Devpost pages. The live demo answers `GET` with 200 (its HTTP API returns 404 to `HEAD`) |

## Live demo

Base URL: `https://7bs6otuwci.execute-api.ap-southeast-2.amazonaws.com`

| What | Command | Result |
|---|---|---|
| Health and deployed build | `curl.exe -s https://7bs6otuwci.execute-api.ap-southeast-2.amazonaws.com/healthz` | `{"status":"ok","version":"0.1.0","commit":"509b3a62c0f5"}` |
| The UI is served | `(Invoke-WebRequest https://7bs6otuwci.execute-api.ap-southeast-2.amazonaws.com/ -UseBasicParsing).StatusCode` | 200, `text/html`, the page contains "NECROMANCER" |
| Both verdicts, on the live API | the script below | `baseline=NO-GO tightened=GO examples=5000`, 13 s |

The deployed build is `509b3a6`. Commits after it (the accessibility pass, the e2e tests, the redaction fix) are in
the repository and not yet deployed.

```powershell
$u = "https://7bs6otuwci.execute-api.ap-southeast-2.amazonaws.com"
$cfg = [IO.File]::ReadAllText("samples\dead-configs\pix-2006-hq.cfg")
$when = "2026-11-27T10:00:00Z"
$sel = @{ choices = @(@{ finding_id = "AUT-0008" }); approvals = @{ "AUT-0008" = @{
  approval = "accepted"; approver = "A. Reviewer"; decided_at = $when; reason = "telnet is not needed" } } }
$side = @{ ledger_decisions = @{ "LED-0001" = @{
  approval = "accepted"; approver = "A. Reviewer"; decided_at = $when; reason = "profile reviewed" } } }
$body = @{ config = $cfg; dialect = "pix"; sample = "pix-2006-hq"; name = "pix-2006-hq"
  tightening = $sel; sidecar = $side } | ConvertTo-Json -Depth 8
$r = Invoke-RestMethod -Uri "$u/v1/gate" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 90
"baseline=$($r.verdict.value) tightened=$($r.tightened.verdict.value) examples=$($r.examples_per_context)"
```

## Reproduce everything

```powershell
cd backend
$env:UV_PYTHON_PREFERENCE = 'only-system'
uv sync --locked
uv run ruff check . ; uv run ruff format --check . ; uv run mypy --strict necro
uv run pytest -q -m "not perf" --cov=necro --cov-fail-under=90
$env:HYPOTHESIS_PROFILE = 'ci'; uv run --with pytest-xdist==3.6.1 pytest -q -m pbt -n auto
cd ..\frontend
npm.cmd ci ; npm.cmd test ; npm.cmd run build ; npm.cmd run e2e:install ; npm.cmd run e2e
cd .. ; python -I .github/scripts/check_repo.py ; python -I .github/scripts/check_docs.py
```
