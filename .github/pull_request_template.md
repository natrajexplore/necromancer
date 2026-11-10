## What and why
<!-- One or two sentences. Link the spec task or issue this closes. -->

Closes #
Spec task: <!-- e.g. necro-engine/2.3 (or n/a) -->

## Type of change
- [ ] Spec task implemented in Kiro (`kiro-task:` trailer on the commits)
- [ ] Migration semantics fix (steering + golden flow updated)
- [ ] Specs / steering / samples / golden flows
- [ ] Docs
- [ ] CI / repo tooling

## Evidence
<!-- Paste what proves it works: test output, proof result (profile, examples, seed, divergences, rule coverage),
     golden-flow results, verdict output, screenshots for UI changes. -->

## Checklist
- [ ] **Synthetic data only**: no real configs, public IPs outside RFC 5737, hostnames, company names or secrets
- [ ] `python -I .github/scripts/check_repo.py` passes
- [ ] Backend/frontend checks pass locally (ruff, mypy, pytest + coverage, PBT at `ci`, golden flows, npm build/test)
- [ ] No gate weakened (coverage threshold, Hypothesis budgets, verdict rules, golden-flow expectations)
- [ ] Nothing dropped or widened silently: untranslatable behaviour is an unparsed line or a ledger entry
- [ ] Spec traceability kept: new acceptance criteria have tasks, and the completed task is ticked in `tasks.md`
- [ ] Semantics changes cite vendor documentation (document, section, OS version) and update `policy-semantics.md`
- [ ] No "compliant" / "safe to deploy" wording
- [ ] `.kiro/` is not git-ignored

## Reviewer notes
<!-- Anything the reviewer should look at first, risks, follow-ups. Four-eyes: the reviewer must not be the author. -->
