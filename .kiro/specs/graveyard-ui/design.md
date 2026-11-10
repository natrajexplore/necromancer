# Design: graveyard-ui

## Routes
| Route | Screen |
|---|---|
| `/` | Graveyard (tombstone grid + drop zone) |
| `/crypt/:id` | Autopsy (rule table + ghost badges + filters) |
| `/crypt/:id/rise` | Resurrection (split diff + tightening panel + ledger) |
| `/crypt/:id/proof` | Proof of Life (heartbeat, stats, counterexample card) |
| `/crypt/:id/grimoire` | Themeless verdict + gate table, report preview, runbook, downloads |

## Components
`Tombstone`, `FogLayer` (CSS, disabled under reduced motion), `GhostBadge`, `RuleTable` (virtualized for 5k rules), `SplitConfig`, `LedgerList`, `Heartbeat` (SVG path animated by progress), `CounterexampleCard`, `VerdictBanner` (themeless), `GateTable`, `UnquietLines`, `ZoneMap`, `RunbookList`, `ReportFrame`.

## State
React Query keyed by `cryptId`. The exhumed IR stays in memory on the client and is re-sent on each call (stateless backend, nothing persisted).

## Visual
Tokens from the `haunted-ui` steering doc. Display font is self-hosted under the OFL. Tombstones are pure SVG, drawn by us.

## Testing
Vitest + Testing Library for components. Playwright smoke test for the full ritual on `pix-2006-hq` and on the "Haunt it" path.
