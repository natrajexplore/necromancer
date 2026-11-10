# Requirements: necro-engine

## Introduction
The necro-engine is NECROMANCER's deterministic core. It parses end-of-life Cisco firewall and router
configurations into a vendor-neutral policy IR, finds ghost rules, emits a PAN-OS candidate configuration,
optionally applies zero-trust tightening, and **proves** behavioural equivalence with property-based testing.

Exact semantics live in `.kiro/steering/policy-semantics.md`. Hand-verified acceptance vectors live in
`samples/golden-flows/`. Governance (gates, verdict, report, runbook) is specified in
`.kiro/specs/migration-governance/`.

**Phases.** Phase 1 (hackathon MVP, due 2026-11-30) covers criteria marked **[P1]**. Phase 2 (enterprise
hardening) covers **[P2]**. A P2 construct met during Phase 1 must still be reported as a security-relevant
unparsed line, never silently ignored.

## Requirement 1: Exhume (parse dead configs)
**User story:** As a network engineer, I want to paste or upload a legacy config so that its access policy is captured in a form I can analyze.

### Acceptance criteria
1.1 **[P1]** WHEN a Cisco PIX 6.x or ASA 7.x–8.2 config is submitted THE SYSTEM SHALL parse `name`/`names`, `nameif`/`security-level`, interface `ip address`, `route`, `object-group` (network, service with tcp/udp/tcp-udp, protocol, icmp-type, nested `group-object`), `access-list` (extended, incl. `remark`, `log`, `inactive`, `time-range`), `access-group ... in|out interface`, `same-security-traffic`, `nat-control`, and `static`/`nat`/`global` statements into the IR.
1.2 **[P1]** WHEN a Cisco IOS 12.x config is submitted THE SYSTEM SHALL parse standard (1–99, 1300–1999, named) and extended (100–199, 2000–2699, named, with optional sequence numbers) ACLs, `remark`, `established`, interface `ip address` and `ip access-group in|out`, and `ip route`.
1.3 **[P1]** WHEN the dialect is not specified THE SYSTEM SHALL auto-detect dialect, OS version and mode, and report them with a confidence value in [0, 1].
1.4 **[P1]** IF a line can't be parsed THEN THE SYSTEM SHALL record an `UnparsedLine{line_no, text(redacted), reason, security_relevant}` and continue. It SHALL NOT abort the whole parse.
1.5 **[P1]** IF nested object-groups form a cycle THEN THE SYSTEM SHALL raise a `ParseError` naming the cycle path; IF an ACE references an undefined object or group THEN THE SYSTEM SHALL raise a `ParseError` with the line number (fixtures in `samples/broken-configs/`).
1.6 **[P1]** WHEN secrets appear (see security steering) THE SYSTEM SHALL redact them before anything else stores, logs, displays or returns them (property P10).
1.7 **[P1]** WHEN rules are marked `inactive` THE SYSTEM SHALL keep them in the IR, flagged, and exclude them from evaluation.
1.8 **[P1]** THE SYSTEM SHALL satisfy round-trip property P1 for each supported dialect.
1.9 **[P1]** THE SYSTEM SHALL classify every input line exactly once as `migrated`, `not-policy`, `management-plane`, `out-of-scope` or `unparsed`, and report coverage = migrated ÷ security-relevant lines (property P14).
1.10 **[P1]** THE SYSTEM SHALL resolve port, ICMP-type and IP-protocol names using tables keyed by protocol (policy-semantics §4). An unknown name SHALL be a security-relevant unparsed line.
1.11 **[P1]** THE SYSTEM SHALL classify IOS ACLs by what references them (interface binding = policy; `access-class`, SNMP, NTP, HTTP = management-plane; route-map/NAT/crypto/QoS = not-policy; none = unused).
1.12 **[P1]** WHEN the config uses an out-of-scope mode or construct (transparent mode, multiple context, IPv6, FQDN objects, `conduit`/`outbound`, identity/TrustSec ACEs, reflexive ACLs, ZBFW/CBAC, ICMP code keywords, `fragments`, QoS match keywords, non-contiguous wildcards) THE SYSTEM SHALL record it as out-of-scope or security-relevant unparsed with a specific reason (fixtures in `samples/broken-configs/`).
1.13 **[P2]** WHEN an ASA 8.3–9.x config is submitted THE SYSTEM SHALL parse `object network` (host, subnet, range), `object service`, `network-object object`, `service-object`, object NAT, twice NAT (static, no service translation), `any4`, `interface <nameif>` operands and `access-group ... global` (fixture `asa-9.8-dc.cfg`).
1.14 **[P2]** WHEN `show access-list` output is supplied with the config THE SYSTEM SHALL attach per-ACE hit counts to rules.

## Requirement 2: Evaluate (single source of truth)
**User story:** As the system, I need one exact evaluator so that autopsy, gates and proof agree.

2.1 **[P1]** THE SYSTEM SHALL provide `decide(policy, context, flow) -> Decision{action, rule_id, to_zone, reason}` using first-match semantics and the implicit final deny.
2.2 **[P1]** THE SYSTEM SHALL support protocols ip/tcp/udp/icmp/numbered, source and destination port operators eq/neq/lt/gt/range, ICMP types and the IOS `established` flag.
2.3 **[P1]** THE SYSTEM SHALL be total over well-formed flows (property P8).
2.4 **[P1]** THE SYSTEM SHALL model the implicit behaviours in policy-semantics §1.2–1.5, §2 and §3: the ASA/PIX security-level permit for interfaces without an ACL, the same-security restriction, PIX nat-control `no-translation` deny, IOS permit-all on interfaces without an ACL, and ingress-then-egress evaluation of outbound ACLs.
2.5 **[P1]** THE SYSTEM SHALL derive `to_zone` by longest-prefix match over connected and static routes, returning `self` for the device's own interface addresses (policy-semantics §5).
2.6 **[P2]** THE SYSTEM SHALL evaluate the ASA global ACL after the interface ACL and remove the security-level implicit permit when a global ACL exists.
2.7 **[P1]** THE SYSTEM SHALL pass 100% of the golden flows in `samples/golden-flows/` for every supported dialect (ASA 8.3+ vectors from Phase 2).

## Requirement 3: Autopsy (ghost-rule findings)
**User story:** As a security engineer, I want to see which rules are dead, risky or redundant before migrating, so I don't carry the ghosts forward.

3.1 **[P1]** THE SYSTEM SHALL flag **shadowed** rules (fully covered by the union of earlier rules, so they never match) and name the shadowing rule(s).
3.2 **[P1]** THE SYSTEM SHALL flag **redundant** rules (covered by a later rule with the same action and no conflicting rule between them).
3.3 **[P1]** THE SYSTEM SHALL flag **overly broad** permits (`any` source and `any` destination, or `ip` protocol with `any` destination).
3.4 **[P1]** THE SYSTEM SHALL flag permits of **insecure services**: telnet/23, ftp/21, tftp/69, rsh-rlogin-rexec/512–514 tcp, snmp/161–162 udp, finger/79, netbios/137–139 and smb/445 from untrusted zones, RDP/3389 and http/80 to management ranges, and cleartext ldap/389, pop3/110, imap/143 from untrusted zones.
3.5 **[P1]** THE SYSTEM SHALL flag **unused objects and object-groups** and **unused ACLs**.
3.6 **[P1]** Each finding SHALL include id, type, severity (critical/high/medium/low per the governance severity model, using the source zone's trust), the rule reference, related rule references, a plain-English explanation, a recommendation and a themed label.
3.7 **[P1]** Removing any rule flagged as shadowed or redundant SHALL change no decision (property P3).
3.8 **[P1]** THE SYSTEM SHALL flag **insecure management**: telnet allowed to the device (`telnet` command, vty `transport input telnet`), HTTP management without TLS, and SNMP v1/v2c communities.
3.9 **[P1]** THE SYSTEM SHALL flag **unfiltered interfaces** (no ACL bound inbound), naming the implicit behaviour that applies.
3.10 **[P1]** THE SYSTEM SHALL flag IOS **return-traffic** rules (`established`, or source-port-only return permits) as low/medium candidates for removal after migration.
3.11 **[P2]** THE SYSTEM SHALL flag **correlated** rules (partial overlap with an earlier rule of the opposite action) as medium.
3.12 **[P2]** WHEN hit counts are available THE SYSTEM SHALL flag **zero-hit** rules, stating the capture age.
3.13 **[P1]** THE SYSTEM SHALL flag rules with **no remark** (no recorded business justification) as low.
3.14 **[P1]** Seeded-ghost recall on `samples/dead-configs/` SHALL be 100% (every `! GHOST: <type>` annotation found on the line below it). Extra findings SHALL be listed in the test output with a justification.

## Requirement 4: Resurrect (emit PAN-OS)
**User story:** As an engineer, I want a ready-to-review PAN-OS candidate config that behaves like the original.

4.1 **[P1]** THE SYSTEM SHALL emit PAN-OS `set` commands for zones (one per `nameif` / interface), address objects and groups, service objects and groups, custom applications needed for ICMP types and IP protocols, and security rules in the original order.
4.2 **[P1]** THE SYSTEM SHALL emit an explicit final deny rule (logging on), and SHALL emit explicit allow rules that reproduce implicit permits (security-level and IOS no-ACL), each tagged `necro:implicit`.
4.3 **[P1]** IF a construct can't be represented exactly THEN THE SYSTEM SHALL add an exorcism ledger entry with a class from policy-semantics §7. Nothing lossy may be silent.
4.4 **[P1]** Emitted names SHALL be deterministic, valid PAN-OS identifiers (≤ 63 characters, `[A-Za-z0-9_.-]`, starting with an alphanumeric) and collision-free (property P12).
4.5 **[P1]** THE SYSTEM SHALL set each rule's to-zone from route derivation, splitting a rule per to-zone when its destination spans several egress interfaces, while preserving first-match order.
4.6 **[P1]** THE SYSTEM SHALL emit port-based like-for-like rules (`application any` + explicit service). It SHALL NOT use `application-default` in the baseline output.
4.7 **[P1]** THE SYSTEM SHALL emit ICMP-type-restricted rules with custom applications that match the exact types, and SHALL NOT widen to the `ping`/`icmp` App-IDs except through an accepted ledger entry.
4.8 **[P1]** THE SYSTEM SHALL emit `inactive` rules as `disabled yes`, remarks as descriptions, the tag `src-acl:<acl>` on every rule, and `log-end yes` on allow rules.
4.9 **[P1]** THE SYSTEM SHALL omit IOS `established` ACEs and create a `stateful-established` ledger entry for each.
4.10 **[P1]** THE SYSTEM SHALL map to-the-box rules and management commands (`telnet`/`ssh`/`http` on ASA, vty `access-class` on IOS) to interface management profiles with permitted IPs, with a `to-the-box` ledger entry.
4.11 **[P1]** THE SYSTEM SHALL apply the NAT address-space rules (policy-semantics §1.5): pre-8.3 ACL addresses kept as pre-NAT, zone from the real address.
4.12 **[P2]** THE SYSTEM SHALL translate 8.3+ real destinations to mapped addresses for flows arriving on the NAT's mapped interface, and emit PAN-OS NAT rules for static and dynamic (PAT) NAT (property P13).
4.13 **[P2]** THE SYSTEM SHALL emit `time-range` as PAN-OS schedule objects with a `time-range` ledger entry.
4.14 **[P1]** THE SYSTEM SHALL produce byte-identical output for the same input and options (property P11), and SHALL never connect to or push configuration to any device.
4.15 **[P2]** THE SYSTEM SHALL optionally emit Panorama device-group / template-scoped output and PAN-OS XML (`load config partial`) in addition to `set` commands.

## Requirement 5: Zero-trust tightening + exorcism ledger
**User story:** As a security architect, I want to optionally tighten the policy during migration, with every behavioural change recorded.

5.1 **[P1]** WHEN tightening is enabled THE SYSTEM SHALL offer per-finding remediation choices: remove shadowed or redundant rules, replace insecure services with secure ones (telnet→ssh, ftp→sftp, http→https, snmp v2c→v3 note), and narrow `any` to object groups the user confirms.
5.2 **[P1]** Every change that alters a decision SHALL produce a ledger entry: `{id, class, reason, affected_match, context, old_action, new_action, finding_ref, approval: pending|accepted|rejected, approver, decided_at}`.
5.3 **[P1]** Tightening SHALL be monotone (property P6).
5.4 **[P1]** THE SYSTEM SHALL keep the baseline (like-for-like) and tightened outputs as separate artifacts, each with its own proof result (governance rule R1).

## Requirement 6: Proof of Life (property-based oracle)
**User story:** As a change approver, I want evidence that the new policy behaves like the old one, so I can approve the migration.

6.1 **[P1]** THE SYSTEM SHALL check property P2 (equivalence of action and to-zone, modulo the ledger) using Hypothesis with boundary-biased flow strategies, comparing against the IR **re-read from the emitted PAN-OS text**.
6.2 **[P1]** THE SYSTEM SHALL support example budgets of 500 / 5,000 / 10,000 (dev / ci / demo profiles) per context and cap requests at 20,000.
6.3 **[P1]** WHEN a divergence is found THE SYSTEM SHALL return the **shrunk** counterexample flow, the context, and both decisions, rule IDs and to-zones.
6.4 **[P1]** WHEN no divergence is found THE SYSTEM SHALL return, per context, the count of examples checked, the coverage (% of active rules hit at least once on each side, plus the list of rules not hit) and the seed, so the run is reproducible.
6.5 **[P1]** THE SYSTEM SHALL complete a 10,000-example proof on each sample config in under 15 s on a Lambda with 1,769 MB memory.
6.6 **[P1]** THE SYSTEM SHALL include implicit contexts (interfaces without an ACL) in the proof.
6.7 **[P1]** The mutation sanity suite (pbt-playbook) SHALL make P2 fail with a shrunk counterexample for every mutant.
6.8 **[P1]** THE SYSTEM SHALL run the golden flows as part of every proof and report their results separately.

## Requirement 7: Interfaces
7.1 **[P1]** THE SYSTEM SHALL produce the Grimoire report as specified in `migration-governance` (Requirement 4 there).
7.2 **[P1]** THE SYSTEM SHALL expose `POST /exhume`, `/autopsy`, `/resurrect`, `/prove`, `/gate`, `/grimoire` and `GET /healthz` over HTTP (FastAPI), with versioned pydantic request/response schemas (`/v1/...`).
7.3 **[P1]** THE SYSTEM SHALL expose `exhume`, `autopsy`, `resurrect`, `prove` and `gate` as MCP tools over stdio.
7.4 **[P1]** THE SYSTEM SHALL provide a CLI: `necro exhume|autopsy|resurrect|prove|gate|grimoire <file>` with `--format json|md|text`, `--seed`, `--profile`, and exit codes 0 = GO/pass, 1 = NO-GO/divergence, 2 = input error.
7.5 **[P1]** THE SYSTEM SHALL enforce the limits in the security steering (2 MB, 10 s parse timeout, 20,000 examples, rate limit) and return structured errors `{code, message, line_no?}` (422 for parse errors with line numbers).

## Requirement 8: Non-functional
8.1 **[P1]** Parsing and autopsy of a 5,000-rule config SHALL complete in under 5 s on the Lambda profile.
8.2 **[P1]** `mypy --strict` and `ruff` SHALL pass on `necro/`. Line coverage on `necro/` SHALL be ≥ 90%.
8.3 **[P1]** The engine SHALL make no network calls (enforced by a test that blocks sockets during the suite).
8.4 **[P1]** CI SHALL run lint, types, unit tests, PBT at the `ci` profile, golden flows and dependency audits on every push.
