# Samples

All configs here are **synthetic**. They use RFC 5737 / RFC 1918 addresses and fake secrets. Never add real configs.

| Folder | Purpose |
|---|---|
| `dead-configs/` | Positive fixtures, one per supported dialect/version: PIX 6.3, ASA 8.2 (pre-8.3 NAT), ASA 9.8 (object NAT, global ACL; Phase 2), IOS 12.4 |
| `broken-configs/` | Negative fixtures: object-group cycle, undefined group, unsupported IOS constructs, out-of-scope mode |
| `golden-flows/` | Hand-verified expected decisions for each dead config (see its README) |

## Annotations (comment lines, on the line directly above the line they describe)

| Annotation | Meaning | Checked by |
|---|---|---|
| `! GHOST: <type> (<why>)` | A seeded autopsy finding. Types: `shadowed`, `redundant`, `overly-broad`, `insecure-service`, `unused-object`, `insecure-management`, `unfiltered-interface`, `return-traffic` | `test_autopsy_recall.py` (100% recall) |
| `! UNSUPPORTED: <reason>` | The next line must become a security-relevant unparsed line | `test_coverage.py` |
| `! EXPECT-UNPARSED: <reason>` | Same, in negative fixtures, with an exact reason code | `test_coverage.py` |

## Coverage of migration traps

| Trap | Where |
|---|---|
| Security-level implicit permit (no ACL) | PIX `inside`, golden `PIX-15/16` |
| nat-control (PIX 6.x) | PIX `nat`/`global`/`static` |
| Pre-8.3 ACL uses the mapped address | ASA 8.2 `OUTSIDE_IN#7`, golden `A82-10` |
| 8.3+ ACL uses the real address → PAN-OS pre-NAT IP | ASA 9.8, golden `A98-01..07` |
| Global ACL removes the implicit permit | ASA 9.8, golden `A98-12/13` |
| Same-security inter-interface | ASA 9.8 partner → dmz, golden `A98-08` |
| `neq`, inclusive `range`, nested groups, `tcp-udp` groups | ASA 8.2, IOS golden `IOS-09..11` |
| `inactive` ACE | ASA 8.2 `OUTSIDE_IN#8`, golden `A82-11` |
| `time-range` | ASA 9.8 `OUTSIDE_IN#2`, golden `A98-03` |
| IOS `established` vs PAN-OS sessions | IOS `110#1`, golden `IOS-01/02` |
| IOS interface without an ACL permits all | IOS `FastEthernet0/2`, golden `IOS-13` |
| To-the-box traffic | IOS `110#4`, golden `IOS-04`; `telnet`/`ssh` commands on PIX/ASA |
| ICMP type exactness (no widening to `ping`) | golden `PIX-12`, `IOS-06`, `A98-05` |
| IP protocol numbers (OSPF/EIGRP) | ASA 9.8 `PARTNER_IN#2`, golden `A98-09` |
| IPv6 must not vanish | ASA 9.8 `OUTSIDE_IN#6` |
