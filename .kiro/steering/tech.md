---
inclusion: always
---

# Tech stack & conventions

## Backend (`backend/`)
- Python 3.12 (pinned via `.python-version`), `uv` for env/deps.
- FastAPI + pydantic v2 for the API. `mangum` adapter for AWS Lambda.
- Parsing: hand-written line-oriented tokenizers (no regex soup; one small, anchored, non-backtracking regex per statement type is fine). No heavy parser frameworks.
- Address math: stdlib `ipaddress` only. Golden flows are TOML, read with stdlib `tomllib`.
- Testing: `pytest` + **`hypothesis`** (property-based testing is a first-class requirement, not optional), `pytest-cov`.
- Hypothesis profiles are registered in `tests/conftest.py`: `dev` = 500, `ci` = 5,000, `demo` = 10,000. The active one is
  read from `HYPOTHESIS_PROFILE` and defaults to `dev`, so commands work the same in bash, PowerShell and cmd.
- Lint/format: `ruff check` + `ruff format`. Types: `mypy --strict` on `necro/`.
- Coverage: ≥ 90% lines on `necro/` (CI fails below that).
- MCP server: official `mcp` Python SDK (`FastMCP`), stdio transport.
- Versioning: SemVer in `pyproject.toml`. `necro --version` and every report print the version and git commit.

## Frontend (`frontend/`)
- React 18 + TypeScript + Vite, Tailwind CSS, Framer Motion for the resurrection animation.
- No UI kit with vendor branding. Custom components only.
- State: React Query for API calls; no global store unless needed.

## Deploy
- AWS free tier: S3 + CloudFront for the UI, API Gateway HTTP API + Lambda for FastAPI.
- IaC: AWS SAM (`template.yaml`). Budget alarm at USD 1. API Gateway throttling matches the limits in `security.md`.
- `GET /healthz` returns version and commit.

## CI (`.github/workflows/ci.yml`)
On every push and PR: `ruff check`, `ruff format --check`, `mypy --strict necro`, `pytest` (dev profile) with coverage,
`pytest -m pbt` with `HYPOTHESIS_PROFILE=ci`, golden flows, `pip-audit`, frontend `npm ci && npm run build && npm test`,
`npm audit --audit-level=high`.
The workflow already exists. Its `repo-integrity` job runs `.github/scripts/check_repo.py` (`.kiro` JSON validity, `.kiro`
never git-ignored, spec traceability, sample annotations, synthetic IPs, golden-flow schema). Backend and frontend steps
are gated on `backend/pyproject.toml` and `frontend/package-lock.json`, so they switch on as soon as those files exist.
Keep the exact commands above when extending it; never weaken a gate (e.g. lowering `--cov-fail-under`) to make CI green.

## Commands
- `uv run python -m pytest -q`: all tests
- `uv run python -m pytest -q -m pbt`: property-based tests only
- `uv run python -m pytest -q tests/test_golden_flows.py`: hand-verified vectors
- `uv run python -m ruff check . && uv run python -m mypy necro`
- `npm --prefix frontend run dev|build|test`

## Commit convention
Conventional commits + trailer `kiro-task: <spec>/<task-id>` when the change came from a Kiro spec task.

## Local development on Windows (Smart App Control)
The developer machine runs Windows 11 with **Smart App Control on**. It blocks unsigned executables (os error 4551),
including uv-managed Python builds and many console-script launchers (`pytest.exe`, `mypy.exe`, `necro.exe`).
- Use the **python.org** (signed) Python 3.12 as the interpreter, with `UV_PYTHON_PREFERENCE=only-system`. Never rely on
  `uv python install`.
- Always invoke tools as modules: `uv run python -m pytest`, `python -m ruff`, `python -m mypy`, `python -m uvicorn`.
  Hooks, docs and generated scripts must use this form.
- The CLI must be runnable as `uv run python -m necro ...` (provide `necro/__main__.py`), in addition to the `necro`
  console script.
- Frontend: Node and Vite (esbuild, rollup) run fine. In PowerShell call `npm.cmd`/`npx.cmd`, or set
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
- CI (Linux) is unaffected.
