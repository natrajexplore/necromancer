# Requirements: migration-governance

## Introduction
Turns the necro-engine's results into the evidence a regulated organization needs to approve a firewall migration:
validation gates, a readiness verdict, the Grimoire report, and a cutover/rollback runbook. The mandatory phases,
gates, severity model and control mapping are defined in `.kiro/steering/migration-governance.md`.

NECROMANCER never connects to devices and never claims compliance. It "supports evidence for" controls.

Phase markers **[P1]** / **[P2]** have the same meaning as in the necro-engine spec.

## Requirement 1: Validation gates
**User story:** As a change approver, I want objective pass/fail gates so that a migration can't be approved on opinion alone.

1.1 **[P1]** THE SYSTEM SHALL evaluate gates G1–G6 exactly as defined in the governance steering, each returning `{gate, status: pass|fail|waived, checks[], blocking_reasons[]}`.
1.2 **[P1]** G1 SHALL fail WHEN dialect confidence < 0.9, the OS version is unsupported, or the mode isn't routed single-context.
1.3 **[P1]** G2 SHALL fail WHEN any security-relevant line is unparsed or out-of-scope and not waived.
1.4 **[P1]** G3 SHALL run static validation of the emitted PAN-OS config (name validity and uniqueness, reference resolution, empty groups, zones on every rule, explicit final deny present, `any`→`any` allow only with a ledger entry), reporting errors and warnings separately.
1.5 **[P1]** G4 SHALL fail WHEN the proof ran below the `ci` budget for any context, when any divergence lies outside the ledger, or when any golden flow fails. It SHALL list active rules not hit on either side as warnings.
1.6 **[P1]** G5 SHALL fail WHEN any ledger entry is `pending`.
1.7 **[P1]** G6 SHALL fail WHEN any critical finding is open without an accepted-risk record.

## Requirement 2: Readiness verdict, waivers and approvals
**User story:** As a CAB member, I want a single verdict with the reasons on top, so I can decide quickly and defensibly.

2.1 **[P1]** THE SYSTEM SHALL compute the verdict `GO` (all pass), `CONDITIONAL` (passes only via valid waivers or accepted risks) or `NO-GO`, with blocking reasons ordered by gate.
2.2 **[P1]** A waiver SHALL record `{target (line/finding/ledger id), reason, approver, expires_on}`. An expired waiver SHALL count as missing.
2.3 **[P1]** THE SYSTEM SHALL accept change metadata `{change_id, requested_by, peer_reviewer, cab_reference, window_start, window_end}` and SHALL show `CONDITIONAL` instead of `GO` WHEN the peer reviewer equals the requester (four-eyes rule).
2.4 **[P1]** The verdict SHALL never use the words "compliant" or "safe to deploy" (asserted by a test).

## Requirement 3: Audit trail and determinism
3.1 **[P1]** Every report and API result SHALL carry an audit header: tool version + git commit, SHA-256 of every input, dialect + OS version, options, seed, budget, profile, UTC timestamp, and SHA-256 of every output artifact.
3.2 **[P1]** WHEN run twice with the same inputs, options and seed THE SYSTEM SHALL produce byte-identical report bodies and configs (only the header timestamp may differ).
3.3 **[P1]** THE SYSTEM SHALL include only the **redacted** source config in any artifact.

## Requirement 4: Grimoire report
**User story:** As an engineer, I want one document I can attach to the change record.

4.1 **[P1]** THE SYSTEM SHALL produce the report sections in the order listed in governance steering §5, in Markdown and in print-friendly HTML.
4.2 **[P1]** THE SYSTEM SHALL include the zone mapping table (interface, nameif, security level, PAN-OS zone) and the address-space assumption.
4.3 **[P1]** THE SYSTEM SHALL include a zone-to-zone matrix of allowed services, before and after (baseline and, if present, tightened).
4.4 **[P1]** THE SYSTEM SHALL include a rule inventory with a business-justification column pre-filled from remarks, to support PCI DSS 1.2.5 review.
4.5 **[P1]** THE SYSTEM SHALL include the control-mapping table from the governance steering with the "supports evidence for" wording.
4.6 **[P1]** THE SYSTEM SHALL recommend rotating every redacted shared secret (counted by type, never shown).
4.7 **[P2]** THE SYSTEM SHALL export the report as PDF and the findings/ledger as CSV.

## Requirement 5: Runbook
**User story:** As the implementing engineer, I want ready-made checklists and command lists for the change window.

5.1 **[P1]** THE SYSTEM SHALL generate a pre-cutover checklist (P6 in the governance steering), including loading the candidate and running `validate full` without committing, interface/zone mapping, routes, NAT, HA, log forwarding, and backups of source and target.
5.2 **[P1]** THE SYSTEM SHALL generate target verification commands `test security-policy-match from <zone> to <zone> source <ip> destination <ip> destination-port <port> protocol <n>` for every golden flow and for a deterministic sample of oracle flows covering every rule, each with its expected result.
5.3 **[P1]** WHEN the source is ASA ≥ 7.2 THE SYSTEM SHALL generate matching `packet-tracer input <nameif> <proto> <src> <sport> <dst> <dport>` baseline commands for the source.
5.4 **[P1]** THE SYSTEM SHALL generate a rollback section with default triggers (verification mismatch, P1/P2 incident, application owner request), a decision time limit, and steps.
5.5 **[P1]** THE SYSTEM SHALL generate a post-cutover/hypercare checklist listing the rules to watch (ledger entries, rules with low proof coverage, tightened rules).

## Requirement 6: Interfaces
6.1 **[P1]** THE SYSTEM SHALL expose `POST /v1/gate` (gates + verdict) and include the verdict in `POST /v1/grimoire`, the CLI (`necro gate`, exit code 0 = GO/CONDITIONAL, 1 = NO-GO) and the MCP tool `gate`.
6.2 **[P1]** Waivers, approvals and change metadata SHALL be supplied as a JSON/TOML sidecar file (CLI) or request body (API). The hosted demo SHALL NOT store them.
