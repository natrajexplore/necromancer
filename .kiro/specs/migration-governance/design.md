# Design: migration-governance

## Flow
```
Policy IR ─┬─ coverage ─────────────┐
           ├─ autopsy findings ─────┤
           ├─ emitted PAN-OS ─► validate_panos ─┤
           ├─ ProofResult (+ golden) ───────────┼─► gates.evaluate(...) ─► Verdict ─┬─► report.render_md / render_html
           └─ ledger ───────────────┘          ▲                                   └─► runbook.build(...)
                         Sidecar (waivers, approvals, change metadata)
```

## Models (`necro/gates.py`)
```python
class Waiver(BaseModel):
    target: str               # "line:57" | "finding:F-012" | "ledger:L-003"
    reason: str
    approver: str
    expires_on: date

class ChangeMeta(BaseModel):
    change_id: str | None = None
    requested_by: str | None = None
    peer_reviewer: str | None = None
    cab_reference: str | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None

class Sidecar(BaseModel):     # loaded from JSON or TOML
    waivers: list[Waiver] = []
    ledger_decisions: dict[str, Literal["accepted", "rejected"]] = {}
    accepted_risks: list[Waiver] = []
    change: ChangeMeta = ChangeMeta()

class Check(BaseModel):
    id: str; ok: bool; severity: Literal["error", "warning"]; detail: str

class GateResult(BaseModel):
    gate: Literal["G1", "G2", "G3", "G4", "G5", "G6"]
    status: Literal["pass", "fail", "waived"]
    checks: list[Check]
    blocking_reasons: list[str]

class Verdict(BaseModel):
    value: Literal["GO", "CONDITIONAL", "NO-GO"]
    gates: list[GateResult]
    blocking_reasons: list[str]
    waivers_used: list[Waiver]
    audit: AuditHeader
```
`gates.evaluate(policy, findings, emitted, validation, proof, ledger, sidecar, today) -> Verdict` is a pure function. `today`
is injected so waiver-expiry tests are deterministic.

## Static validation (`necro/validate_panos.py`)
Works on the IR produced by `panos_reader` plus the raw set lines. Checks: name regex `^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`,
uniqueness per namespace, every referenced address/service/application/schedule/zone/profile exists, no empty groups,
every rule has `from`/`to`, the last rule is a deny with `any`/`any`, and no allow with `source any` + `destination any` +
`service any` unless a ledger entry references that rule.

## Report (`necro/report.py`)
- Jinja-free: f-strings plus small helpers, so there's no template injection surface. HTML escapes every value from the IR.
- `render_md(verdict, ...)` and `render_html(...)` produce the same sections. The HTML has print CSS and no external assets.
- The control-mapping and severity tables are loaded from one Python constant that mirrors the steering doc. A test asserts
  they match the steering doc's table rows, so they can't drift apart.

## Runbook (`necro/runbook.py`)
- Verification flow selection: all golden flows, plus for each active rule the first oracle example that hit it
  (deterministic by seed), capped at 200 commands.
- PAN-OS command: `test security-policy-match from {fz} to {tz} source {src} destination {panos_dst} destination-port {dport} protocol {n}`.
  ICMP flows use `protocol 1` with no port. Expected = rule name or the final deny name.
- ASA command (≥ 7.2): `packet-tracer input {nameif} {tcp|udp|icmp|rawip} {src} {sport|type} {dst} {dport|code}`. Expected = ALLOW/DROP.
- Rollback triggers and hypercare duration have defaults, which the sidecar can override.

## Testing
- `test_gates.py`: one test per gate condition, with both a pass and a fail case.
- Verdict matrix test: every combination of gate outcomes maps to the documented verdict.
- Waiver expiry boundary (expires today = still valid; yesterday = expired).
- Four-eyes rule test.
- Report determinism (PBT P11) and a "no forbidden words" test ("compliant", "safe to deploy").
- Golden runbook snapshot for each sample config.
