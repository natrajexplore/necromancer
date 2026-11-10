# Requirements: graveyard-ui

## Introduction
The haunted web UI for NECROMANCER. A spooky skin over a serious workflow: Graveyard → Autopsy → Resurrection → Proof of Life → Grimoire. It must work for judges with no login, no keys and no setup.

## Requirement 1: Graveyard (landing)
1.1 WHEN the app loads THE SYSTEM SHALL show a graveyard with one tombstone per bundled sample config (name, dialect, "died" year, rule count) and an "Exhume your own" tombstone.
1.2 WHEN a user drops or pastes a config THE SYSTEM SHALL call `/exhume` and add a new tombstone, showing the detected dialect, OS version, confidence, the coverage % and the count of unparsed lines (security-relevant ones highlighted).
1.3 THE SYSTEM SHALL state that uploaded configs aren't stored, and that only synthetic configs should be used on the public demo.

1.4 WHEN exhume reports security-relevant unparsed or out-of-scope lines THE SYSTEM SHALL list them as "unquiet lines" with line number, redacted text and reason, and SHALL NOT hide them behind the theme.

## Requirement 2: Autopsy view
2.1 WHEN a tombstone is opened THE SYSTEM SHALL list the rules in order, with ghost findings rendered as ghost badges (severity colour) and plain-English tooltips.
2.2 THE SYSTEM SHALL let the user filter by finding type and severity.
2.3 Clicking a shadowed rule SHALL highlight the rule that shadows it.
2.4 THE SYSTEM SHALL show the zone mapping (interface, security level, PAN-OS zone) and mark unfiltered interfaces.

## Requirement 3: Resurrection
3.1 WHEN the user clicks "Resurrect" THE SYSTEM SHALL play a ≤ 2.5 s rising animation (none when `prefers-reduced-motion` is set) and show the PAN-OS config side by side with the original.
3.2 THE SYSTEM SHALL provide a "Zero-trust tightening" panel to accept or reject each remediation, updating the exorcism ledger live.

## Requirement 4: Proof of Life
4.1 WHEN the user clicks "Prove" THE SYSTEM SHALL show a live heartbeat with flows checked, divergences found and rule coverage on each side.
4.2 WHEN a divergence exists THE SYSTEM SHALL show "the packet that refused to rest": the 5-tuple, the context, and the decision and matching rule on each side.
4.3 THE SYSTEM SHALL offer a "Haunt it" demo toggle that uses the deliberately broken emitter, so the counterexample path can be shown on stage.
4.4 THE SYSTEM SHALL show results per context (including implicit contexts) and the golden-flow pass count separately from the generated flows.

## Requirement 5: Verdict and Grimoire
5.1 THE SYSTEM SHALL let the user download the report (Markdown + print-friendly HTML/PDF), the baseline PAN-OS config (.txt) and, if tightening was applied, the tightened config as a separate file.
5.2 THE SYSTEM SHALL show the readiness verdict (GO / CONDITIONAL / NO-GO) with the gate table and blocking reasons first, in plain language with no spooky labels.
5.3 THE SYSTEM SHALL show the runbook (pre-checks, verification commands, rollback) with copy buttons.

## Requirement 6: Quality
6.1 All text meets WCAG AA contrast. Everything works by keyboard. Focus states are visible.
6.2 Lighthouse performance ≥ 85 on desktop.
6.3 No vendor logos or trademarked imagery.
