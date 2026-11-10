# Golden flows (hand-verified test vectors)

Each `.toml` file lists flows whose expected decision on the **original** config was worked out by hand
from the vendor semantics in `.kiro/steering/policy-semantics.md`. They are an oracle that is independent
of `evaluate.py`: if the evaluator and a golden flow disagree, the evaluator is wrong until a human proves
otherwise. Changing an expectation needs a review comment that cites the semantics rule.

Field reference:

| Field | Meaning |
|---|---|
| `context` | `<ingress nameif or interface>:in` |
| `protocol` | `tcp`, `udp`, `icmp` or an IP protocol number |
| `src`, `dst` | Addresses **as the source device's ACL sees them** (mapped for PIX/ASA <= 8.2, real for ASA >= 8.3, as-is for IOS) |
| `sport`, `dport` | TCP/UDP only |
| `icmp_type` | ICMP only |
| `established` | IOS only; TCP ACK or RST set. Defaults to false |
| `expect_action` | `permit` or `deny` |
| `expect_rule` | `<acl>#<seq>` (seq = 1-based ACE ordinal in that ACL, remarks excluded), or one of `implicit-deny`, `implicit-security-level`, `implicit-permit-no-acl`, `same-security-deny` |
| `expect_to_zone` | Egress zone from the route lookup on the post-NAT destination, or `self` for traffic to the device |
| `expect_panos_dst` | Destination IP a PAN-OS security rule must match (pre-NAT). Only given when it differs from `dst` |
| `expect_ledger` | Ledger class that must cover this flow on the resurrected side, if any |

Tests: `backend/tests/test_golden_flows.py` runs every vector against `decide(original)` and, after
resurrection, against `decide(panos_reader(emit(original)))`, honouring `expect_ledger`.
