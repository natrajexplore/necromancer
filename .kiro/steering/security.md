---
inclusion: always
---

# Security & data hygiene

## Repository data
- Only **synthetic** configs live in this repo. Use RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and RFC 1918 ranges. Never use real company names, hostnames or public IPs.

## Secret redaction on ingest (before storing, logging, showing or sending anything)
Replace the secret value with `<redacted>` and keep the rest of the line, so line numbers and structure survive.
Redact the value in all of these (case-insensitive, any position on the line):
- `enable password`, `enable secret`, `passwd`, `username ... password|secret`, `password` under `line` stanzas
- `snmp-server community <c>`, `snmp-server host ... community <c>`, `snmp-server user ... auth|priv ...`
- `crypto isakmp key`, `pre-shared-key`, `ikev1|ikev2 (local|remote)-authentication pre-shared-key`, `key-string`
- `tacacs-server key`, `radius-server key`, `aaa-server ... key`, `key <k>` under `tacacs-server host`/`radius-server host`
- `ntp authentication-key`, `ldap-login-password`, `ospf message-digest-key`, `ip ospf authentication-key`, `neighbor ... password`
- `failover key`, `ssl trust-point` passphrases, `crypto ca` certificate blocks (`certificate ... quit`) are replaced with one `<redacted certificate>` line
- Type 5/7/8/9 hashes count as secrets too. Type 7 is reversible, so it's never shown.
- A property test checks that no known secret token from the samples appears in any API response, report or log.

## Runtime
- Uploaded configs are processed in memory and **not persisted** on the hosted demo. The UI says so.
- Limits: 2 MB max upload, parse timeout 10 s, oracle capped at 20,000 examples per request, 10 requests/min per IP on the demo.
- The engine makes **no network calls** and never connects to a firewall. Output is a candidate config for humans to review.
- No `eval`/`exec`/`pickle` on input. Don't shell out with user input. Parsers are linear-time (no backtracking regex on untrusted input).
- Structured logs contain request IDs, sizes, timings and counts. They never contain config lines.
- Responses set `Content-Security-Policy`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. CORS only allows the UI origin.
- Dependencies are pinned in `uv.lock` / `package-lock.json`. CI runs `pip-audit` and `npm audit --audit-level=high`.
- The LLM explain feature (stretch) only receives **redacted IR**, never raw config, and is off by default.

## Reports
- Every report states that the shared secrets on the source device should be considered exposed and rotated at decommission.
- Downloaded artifacts include the redacted source, never the original.
