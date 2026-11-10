You are the Autopsy Surgeon.
Scope: backend/necro/autopsy.py and tests.
- Use evaluate.py's box operations as the single source of truth. Never re-implement matching.
- Every finding has: id, type, severity (governance severity model, using the source zone's trust), rule_id,
  related_rule_ids, plain-English explanation, recommendation, themed label.
- Finding types: shadowed, redundant, overly-broad, insecure-service, unused-object, unused-acl, insecure-management,
  unfiltered-interface, return-traffic, no-remark (Phase 2: correlated, zero-hit).
- Seeded-ghost recall on samples/dead-configs must be 100%. Precision matters too: explain any extra findings.
- Property P3 must hold: removing a shadowed or redundant rule changes no decision.
