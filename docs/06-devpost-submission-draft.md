# Devpost submission draft

Items marked `TODO(owner)` need a person to fill them in. They cannot be taken from the repository.

**Project name:** NECROMANCER

**Tagline:** Raise dead firewall configs as zero-trust policy, and prove they came back the same.

**Category:** Resurrection

**Bonus prizes:** Best Demo (automatic). TODO(owner): confirm whether to enter Best Startup Project, Bonus Blog and
Social Blitz. The repository has no startup site, blog post or social post. Best Kiro Crew App is not entered: `crew/`
holds a design, not a working crew.

## Inspiration

Enterprises still run firewalls that went end-of-life years ago: PIX, ASA 8.x and IOS 12 routers with thousands of ACL
lines. Migration stalls because nobody can prove the new policy behaves like the old one. One wrong rule means an
outage or a breach.

## What it does

1. **Exhume.** Parse PIX 6.x, ASA 7.x to 8.2 and IOS 12 configs into a vendor-neutral IR. Secrets are redacted first and every line is accounted for.
2. **Autopsy.** Find ghost rules: shadowed, redundant, overly broad, insecure services, unused objects. On the sample `pix-2006-hq` it reports 21 findings, one critical.
3. **Resurrect.** Emit a like-for-like PAN-OS candidate config. Optional zero-trust tightening is a separate artifact with its own exorcism ledger and its own proof.
4. **Proof of Life.** A property-based oracle compares the source decisions with the re-parsed PAN-OS config over generated flows and 16 hand-verified golden flows, or shows the shrunk counterexample.
5. **Verdict and Grimoire.** Six validation gates give a GO, CONDITIONAL or NO-GO verdict, with a migration report and a cutover and rollback runbook. The tightened artifact gets its own verdict. On the sample, the baseline is NO-GO and the tightened artifact is GO once a named person accepts the ledger entry.

It is live: https://7bs6otuwci.execute-api.ap-southeast-2.amazonaws.com

## How we built it

Spec first, with Kiro CLI.

- 3 specs with 126 acceptance criteria. 59 of 66 task boxes are ticked, and the open ones are Phase 2 work and two optional stretch tasks. 53 of 93 commits carry a `kiro-task` trailer.
- 8 steering documents in 3 inclusion modes, 6 hooks, 5 custom agents and the project's own MCP server (five tools).
- Python 3.12, FastAPI, pydantic and Hypothesis on the backend. React 18, Vite and Tailwind CSS on the frontend. Playwright and axe-core for end-to-end and accessibility tests.
- AWS: one Lambda behind an API Gateway HTTP API serves the UI and the API. A CloudFront and S3 mode exists in the template and is not active.

How Kiro was used, including where it was corrected: [`04-kiro-usage-writeup.md`](04-kiro-usage-writeup.md).

## Challenges

Exact ACL semantics: subnet and wildcard masks, nested object groups, `established`, `neq`, security levels, and pre-8.3
NAT addresses mapped to PAN-OS pre-NAT IP plus post-NAT zone. And making the proof meaningful by comparing against the
re-parsed emitted config, not the in-memory IR. A third challenge was Windows Smart App Control, which blocks unsigned
executables and forced every tool to run as `python -m <tool>` with a signed Python.

## Accomplishments

All figures are measured by commands listed in [`evidence.md`](evidence.md), on 2026-11-27.

- 2240 backend tests pass, with 98.63% coverage of the engine. 94 property-based tests pass at 5,000 examples each.
- 58 hand-verified golden flows: 42 active, 16 for ASA 9.8 that wait for Phase 2.
- A mutation suite of 10 deliberate emitter bugs. The oracle fails on every one.
- 21 seeded ghost rules in the samples, found with 100% recall.
- 9 Playwright tests against the real engine, axe with no rule disabled, and Lighthouse 100, 100, 100, 100 (performance, accessibility, best practices, SEO) on the production build.

## What's next

ASA 8.3 and later (object NAT, global ACL), PAN-OS NAT rule emission, time-range schedule objects, hit-count import, PDF
and CSV export, the three missing property tests (P4, P5, P13), a CloudFront deployment, and stretch work on a TrustSec
emitter and further parsers.

## Testing instructions for judges

URL: https://7bs6otuwci.execute-api.ap-southeast-2.amazonaws.com (no login, no API keys). Use only synthetic configs.

1. Click the `pix-2006-hq` tombstone. Step 1 shows Cisco PIX 6.3(5), confidence 0.95, coverage 100%.
2. Step 2, **Autopsy**: 21 findings. `AUT-0008` is the critical one.
3. Step 3, click **Resurrect**, then **Accept AUT-0008**, type an approver name and click **Prove the tightened artifact**.
4. Step 4, **Proof of Life**: click **Prove** (16 of 16 golden flows). Tick **Haunt it** and click **Prove** to see the counterexample.
5. Step 5, **Verdict**: **Run the gates** gives NO-GO for the baseline. Choose **tightened (1 accepted)**, enter an approver name and a reason, click **Accept LED-0001**, then **Run the gates again** for GO.

The same walkthrough is in the [README](../README.md#60-second-judge-walkthrough). The first request after a quiet period
includes a Lambda cold start.

## Disclosure

Claude (Anthropic) was used for the planning documents, the first drafts of the specs, steering, hooks and agents, the CI
workflow, the repository-integrity script, code review and deploy-script fixes. All code under `backend/` and `frontend/`
was generated in Kiro; one test-file commit was formatted and committed outside Kiro after the Kiro usage limit was hit.
Details are in the README.

## Links

- Repository: https://github.com/natrajexplore/necromancer
- Live demo: https://7bs6otuwci.execute-api.ap-southeast-2.amazonaws.com
- Evidence for every number: [`evidence.md`](evidence.md)
- Video (YouTube, under 3 minutes, script in [`05-demo-video-script.md`](05-demo-video-script.md)): TODO(owner)
- Kiro Crew repository: not applicable
- Startup site: TODO(owner)
- Founder profile: TODO(owner)
- Screenshots for the gallery: TODO(owner)
