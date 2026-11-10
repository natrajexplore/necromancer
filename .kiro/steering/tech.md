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

## Commands
- `uv run pytest -q`: all tests
- `uv run pytest -q -m pbt`: property-based tests only
- `uv run pytest -q tests/test_golden_flows.py`: hand-verified vectors
- `uv run ruff check . && uv run mypy necro`
- `npm --prefix frontend run dev|build|test`

## Commit convention
Conventional commits + trailer `kiro-task: <spec>/<task-id>` when the change came from a Kiro spec task.
