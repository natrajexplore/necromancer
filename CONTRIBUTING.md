# Contributing to NECROMANCER

Thanks for helping raise dead firewalls. NECROMANCER produces evidence that people use to approve production firewall
changes, so the bar is **correctness first, then everything else**. This guide explains how work flows through the repo
and what every change must respect.

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Contents
- [Ground rules](#ground-rules)
- [Ways to contribute](#ways-to-contribute)
- [Development workflow](#development-workflow)
- [Reporting a wrong migration decision](#reporting-a-wrong-migration-decision)
- [Adding or changing semantics](#adding-or-changing-semantics)
- [Samples and golden flows](#samples-and-golden-flows)
- [Specs and steering](#specs-and-steering)
- [Commits and pull requests](#commits-and-pull-requests)
- [Security issues](#security-issues)
- [License](#license)

## Ground rules
These are not negotiable. CI or review will reject a change that breaks one.

1. **Synthetic data only.** Never paste a real config, real hostname, real company name, real public IP or a real
   secret into an issue, commit, sample or test. Use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
   RFC 1918 and RFC 3849 (`2001:db8::/32`) addresses and obviously fake secrets. CI fails on non-synthetic addresses in
   `samples/`. Rules: [`security.md`](.kiro/steering/security.md).
2. **Application code is generated in Kiro.** During the Kiroween submission period (until Dec 4, 2026), code under
   `backend/` and `frontend/` is written by running spec tasks in Kiro, not by hand. Human contributions go into specs,
   steering, samples, golden flows, docs and issues. After the hackathon this rule relaxes, but spec-first stays.
3. **Never git-ignore `.kiro/`** or anything under it. CI checks this.
4. **Nothing silent.** A construct the engine can't translate must become a security-relevant unparsed line that blocks
   the verdict. Never drop, approximate or widen behaviour without a ledger entry.
5. **Like-for-like first.** The baseline translation preserves behaviour exactly. Tightening is a separate output with its
   own ledger and proof.
6. **Never weaken a gate to get green.** Don't lower `--cov-fail-under`, the Hypothesis budgets, the verdict rules or a
   golden-flow expectation to make a failure go away. Fix the cause or open an issue.
7. **Evidence, not claims.** Never write "compliant", "certified" or "safe to deploy" in code, reports or docs. Use
   "supports evidence for".
8. **No device access.** NECROMANCER never connects to or pushes configuration to a device. Don't add features that do.

## Ways to contribute
| You have | Do this |
|---|---|
| A wrong translation or decision | Open a **Migration semantics** issue with a minimal synthetic config and the flow. This is the most valuable report |
| A crash or a broken feature | Open a **Bug report** |
| An idea (new dialect, gate, report section) | Open a **Feature request** with acceptance criteria |
| Vendor documentation that contradicts our steering | Open a Migration semantics issue citing the document, section and version |
| Time to build | Pick an unchecked task in [`.kiro/specs/*/tasks.md`](.kiro/specs) and run it in Kiro |

## Development workflow
1. **Pick a task** from a spec's `tasks.md`. Phase 1 (**[P1]**) tasks come before Phase 2 (**[P2]**).
2. **Run it in Kiro** (IDE "Start task", the CLI or Crew). The steering docs load automatically, and the hooks run the
   proof on save, guard samples and golden flows, block secrets and check traceability.
3. **Check locally**:
   ```bash
   python -I .github/scripts/check_repo.py              # specs, hooks, samples, golden flows (works today)

   cd backend
   uv run ruff check . && uv run ruff format --check .
   uv run mypy --strict necro
   uv run pytest -q --cov=necro --cov-fail-under=90     # dev profile
   HYPOTHESIS_PROFILE=ci uv run pytest -q -m pbt         # proof at the CI budget
   uv run pytest -q tests/test_golden_flows.py

   npm --prefix frontend ci && npm --prefix frontend run build && npm --prefix frontend test
   ```
4. **Tick the task** in `tasks.md` in the same commit, and add three lines to `docs/kiro-journal.md` about what Kiro did
   and what you corrected.
5. **Open a pull request.** CI must be green.

## Reporting a wrong migration decision
A useful report has four parts. The issue form asks for each one.

1. **Minimal synthetic config**: the fewest lines that reproduce the problem (interfaces, the ACL, any NAT and routes).
2. **The flow**: protocol, source, source port, destination, destination port (or ICMP type), ingress interface.
3. **Expected decision on the source device**, with a vendor documentation reference (title, section, OS version) or
   `packet-tracer` output from a lab device using the same synthetic config.
4. **What NECROMANCER did**: its decision, rule and zone, or the PAN-OS rule it emitted.

If you can, add the flow as a proposed golden-flow entry (format below).

## Adding or changing semantics
The single source of truth for vendor behaviour is
[`.kiro/steering/policy-semantics.md`](.kiro/steering/policy-semantics.md). A semantics change is accepted only with:

- a citation (vendor document, section, OS version, date checked) or reproducible lab evidence;
- an update to `policy-semantics.md` in the same pull request;
- at least one **new golden flow** that fails before the fix and passes after it;
- a seeded sample line (and `! GHOST:` / `! UNSUPPORTED:` marker) when the change affects autopsy or coverage;
- if the behaviour can't be expressed on PAN-OS, a ledger class instead of an approximation.

## Samples and golden flows
- **Dead configs** (`samples/dead-configs/`) are positive fixtures, one per dialect/version. **Broken configs**
  (`samples/broken-configs/`) are negative fixtures. See [`samples/README.md`](samples/README.md).
- **Annotations** sit on the line directly above the line they describe: `! GHOST: <type> (<why>)`,
  `! UNSUPPORTED: <reason>`, `! EXPECT-UNPARSED: <reason>`. CI checks the placement.
- **Golden flows** (`samples/golden-flows/*.toml`) are worked out **by hand** from the semantics, never generated from the
  evaluator. If the evaluator and a golden flow disagree, the evaluator is wrong until a human proves otherwise. Changing
  an expectation needs a review comment citing the semantics rule. Field reference:
  [`samples/golden-flows/README.md`](samples/golden-flows/README.md).

  ```toml
  [[flow]]
  id = "A98-14"                       # unique across all files: <prefix>-<nn>
  note = "Why this flow matters, in one line"
  context = "outside:in"              # <ingress nameif or interface>:in
  protocol = "tcp"                    # tcp | udp | icmp | IP protocol number
  src = "192.0.2.10"
  sport = 40000
  dst = "10.60.0.10"                  # as the source ACL sees it (mapped <= 8.2, real >= 8.3)
  dport = 443
  expect_action = "permit"            # permit | deny
  expect_rule = "OUTSIDE_IN#1"        # <acl>#<ordinal> or an implicit-* pseudo rule
  expect_to_zone = "dmz"
  expect_panos_dst = "203.0.113.10"   # only when the PAN-OS (pre-NAT) destination differs
  ```

## Specs and steering
- Acceptance criteria use **EARS** wording (`WHEN ... THE SYSTEM SHALL ...`) and a phase marker (**[P1]**/**[P2]**).
- Every acceptance criterion must be referenced by a task (`_Requirements: x.y_`), and every reference must exist. CI
  checks both directions.
- Keep steering docs short and factual. Put vendor behaviour in `policy-semantics.md`, process and gates in
  `migration-governance.md`, and tooling in `tech.md`.

## Commits and pull requests
- Small commits, conventional prefixes, and a `kiro-task` trailer for work done from a spec task:
  ```
  feat(parser): ASA object-group nesting

  kiro-task: necro-engine/2.3
  ```
- Prefixes: `feat`, `fix`, `test`, `docs`, `spec`, `ci`, `chore`, `refactor`.
- A pull request should state which task or issue it closes, what evidence shows it works (tests, golden flows, proof
  output), and confirm that it contains only synthetic data.

## Security issues
**Don't open a public issue for a vulnerability** (for example, a secret that isn't redacted, or a parser input that
hangs or crashes the service). Report it privately via
[GitHub private vulnerability reporting](https://github.com/natrajexplore/necromancer/security/advisories/new).
Never include real configs or secrets in the report.

## License
By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
