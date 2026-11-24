# Runbook

## 9. Runbook

### Pre-cutover checks (P6)

| Done | ID | Step |
|---|---|---|
| [ ] | PRE-01 | Back up the running configuration of the source and of the target. Record the file names and SHA-256 values with the change record. |
| [ ] | PRE-02 | Load the candidate on the target in configure mode, run validate full, and do not commit. Attach the output. |
| [ ] | PRE-ZONE-01 | Zone outside: replace the placeholder port ethernet1/1 with the real port for source interface GigabitEthernet0/0 (nameif outside, 203.0.113.2/28). |
| [ ] | PRE-ZONE-02 | Zone inside: replace the placeholder port ethernet1/2 with the real port for source interface GigabitEthernet0/1 (nameif inside, 10.50.0.1/24). |
| [ ] | PRE-ZONE-03 | Zone dmz: replace the placeholder port ethernet1/3 with the real port for source interface GigabitEthernet0/2 (nameif dmz, 10.60.0.1/24). |
| [ ] | PRE-ZONE-04 | Zone partner: replace the placeholder port ethernet1/4 with the real port for source interface GigabitEthernet0/3 (nameif partner, 198.51.100.1/24). |
| [ ] | PRE-03 | Compare the 1 static routes of the candidate with show route on the source. Dynamic routing is not migrated; configure and review it separately. |
| [ ] | PRE-04 | Review NAT: the candidate carries 0 translations from the source. Dynamic NAT, PAT and other forms are configured and reviewed separately. |
| [ ] | PRE-05 | Confirm HA pairing and configuration sync on the target. |
| [ ] | PRE-06 | Confirm that log forwarding to the SIEM works on the target: deny and end-of-session logs must arrive. |
| [ ] | PRE-07 | Confirm the baseline capture is less than 7 days old at the cutover, or capture it again and re-run this report. |
| [ ] | PRE-08 | Confirm the CAB approval reference is recorded on the change (now: not recorded) and that a peer reviewer who did not do the translation has signed off. |
| [ ] | PRE-09 | Walk through the rollback section with the team before the window. |

### Cutover steps (P7)

| Done | ID | Step |
|---|---|---|
| [ ] | CUT-01 | Start the change freeze on the source: no rule changes. |
| [ ] | CUT-02 | Apply the candidate on the target and commit. |
| [ ] | CUT-03 | Run the 19 target verification commands and record each result next to its expected result. |
| [ ] | CUT-04 | Run the 19 source packet-tracer commands and record each result. |
| [ ] | CUT-05 | Test the 2 manual checks by another method and record the result. |
| [ ] | CUT-06 | Compare every result with its expected decision. A mismatch is a rollback trigger. |
| [ ] | CUT-07 | Move traffic to the target as the change plan says. |

### Verification commands on the target (PAN-OS)

Run each command in operational mode on the target after the commit. Each one is followed by the result it must give. Golden flows come first, then one oracle flow for every pair of source rule and candidate rule.

| ID | Origin | Context | Command | Expected result |
|---|---|---|---|---|
| A98-01 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.44 destination 203.0.113.10 destination-port 443 protocol 6 | allow; the candidate gives deny by rule OUTSIDE_IN-7, which the proof reports as a failure |
| A98-02 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.44 destination 203.0.113.11 destination-port 80 protocol 6 | allow; the candidate gives deny by rule OUTSIDE_IN-7, which the proof reports as a failure |
| A98-03 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.44 destination 203.0.113.11 destination-port 9005 protocol 6 | allow; the candidate gives deny by rule OUTSIDE_IN-7, which the proof reports as a failure |
| A98-04 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.44 destination 203.0.113.10 protocol 1 | allow; the candidate gives deny by rule OUTSIDE_IN-7, which the proof reports as a failure (ICMP type 8) |
| A98-05 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.44 destination 203.0.113.10 protocol 1 | deny by rule OUTSIDE_IN-7 (ICMP type 3) |
| A98-06 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.44 destination 203.0.113.10 destination-port 21 protocol 6 | allow; the candidate gives deny by rule OUTSIDE_IN-7, which the proof reports as a failure |
| A98-07 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.44 destination 203.0.113.10 destination-port 22 protocol 6 | deny by rule OUTSIDE_IN-7 |
| A98-08 | golden | partner:in | test security-policy-match from partner to dmz source 198.51.100.20 destination 10.60.0.20 destination-port 9001 protocol 6 | allow by rule PARTNER_IN-3 |
| A98-09 | golden | partner:in | test security-policy-match from partner to inside source 198.51.100.20 destination 10.50.0.5 protocol 89 | allow by rule PARTNER_IN-3 |
| A98-10 | golden | partner:in | test security-policy-match from partner to inside source 198.51.100.20 destination 10.50.0.5 destination-port 3389 protocol 6 | allow by rule PARTNER_IN-3 |
| A98-11 | golden | inside:in | test security-policy-match from inside to outside source 10.50.0.20 destination 192.0.2.53 destination-port 53 protocol 17 | allow; the candidate gives deny by rule necro-final-deny, which the proof reports as a failure |
| A98-12 | golden | inside:in | test security-policy-match from inside to outside source 10.50.0.20 destination 192.0.2.80 destination-port 22 protocol 6 | deny by rule necro-final-deny |
| A98-13 | golden | dmz:in | test security-policy-match from dmz to outside source 10.60.0.10 destination 192.0.2.80 destination-port 443 protocol 6 | deny by rule necro-final-deny |
| A98-14 | golden | dmz:in | test security-policy-match from dmz to outside source 10.60.0.10 destination 192.0.2.53 destination-port 53 protocol 17 | allow; the candidate gives deny by rule necro-final-deny, which the proof reports as a failure |
| A98-15 | golden | dmz:in | test security-policy-match from dmz to inside source 10.60.0.10 destination 10.50.0.53 destination-port 53 protocol 17 | deny by rule necro-final-deny |
| A98-16 | golden | dmz:in | test security-policy-match from dmz to inside source 10.60.0.10 destination 10.50.0.30 destination-port 1433 protocol 6 | allow; the candidate gives deny by rule necro-final-deny, which the proof reports as a failure |
| ORC-0001 | oracle | outside:in | test security-policy-match from outside to dmz source 203.0.113.2 destination 10.60.0.10 destination-port 443 protocol 6 | allow by rule OUTSIDE_IN-5 |
| ORC-0002 | oracle | outside:in | test security-policy-match from outside to dmz source 203.0.113.2 destination 10.60.0.10 destination-port 65535 protocol 6 | deny by rule OUTSIDE_IN-7 |
| ORC-0004 | oracle | partner:in | test security-policy-match from partner to outside source 192.0.2.10 destination 203.0.113.1 destination-port 443 protocol 6 | allow by rule PARTNER_IN-3 |

### Verification commands on the source (ASA packet-tracer)

Run these on the source before the freeze ends, to compare with the baseline. packet-tracer exists from ASA 7.2.

| ID | Origin | Context | Command | Expected result |
|---|---|---|---|---|
| A98-01 | golden | outside:in | packet-tracer input outside tcp 192.0.2.44 40000 10.60.0.10 443 | ALLOW (source rule OUTSIDE_IN#1) |
| A98-02 | golden | outside:in | packet-tracer input outside tcp 192.0.2.44 40000 10.60.0.20 80 | ALLOW (source rule OUTSIDE_IN#1) |
| A98-03 | golden | outside:in | packet-tracer input outside tcp 192.0.2.44 40000 10.60.0.20 9005 | ALLOW (source rule OUTSIDE_IN#2) |
| A98-04 | golden | outside:in | packet-tracer input outside icmp 192.0.2.44 8 0 10.60.0.10 | ALLOW (source rule OUTSIDE_IN#3) |
| A98-05 | golden | outside:in | packet-tracer input outside icmp 192.0.2.44 3 0 10.60.0.10 | DROP (source rule OUTSIDE_IN#7) |
| A98-06 | golden | outside:in | packet-tracer input outside tcp 192.0.2.44 40000 10.60.0.10 21 | ALLOW (source rule OUTSIDE_IN#4) |
| A98-07 | golden | outside:in | packet-tracer input outside tcp 192.0.2.44 40000 10.60.0.10 22 | DROP (source rule OUTSIDE_IN#7) |
| A98-08 | golden | partner:in | packet-tracer input partner tcp 198.51.100.20 40000 10.60.0.20 9001 | ALLOW (source rule PARTNER_IN#1) |
| A98-09 | golden | partner:in | packet-tracer input partner rawip 198.51.100.20 89 10.50.0.5 | ALLOW (source rule PARTNER_IN#2) |
| A98-10 | golden | partner:in | packet-tracer input partner tcp 198.51.100.20 40000 10.50.0.5 3389 | ALLOW (source rule PARTNER_IN#3) |
| A98-11 | golden | inside:in | packet-tracer input inside udp 10.50.0.20 50000 192.0.2.53 53 | ALLOW (source rule GLOBAL_POLICY#1) |
| A98-12 | golden | inside:in | packet-tracer input inside tcp 10.50.0.20 50000 192.0.2.80 22 | DROP (source rule implicit-deny) |
| A98-13 | golden | dmz:in | packet-tracer input dmz tcp 10.60.0.10 50000 192.0.2.80 443 | DROP (source rule implicit-deny) |
| A98-14 | golden | dmz:in | packet-tracer input dmz udp 10.60.0.10 50000 192.0.2.53 53 | ALLOW (source rule GLOBAL_POLICY#4) |
| A98-15 | golden | dmz:in | packet-tracer input dmz udp 10.60.0.10 50000 10.50.0.53 53 | DROP (source rule DMZ_IN#2) |
| A98-16 | golden | dmz:in | packet-tracer input dmz tcp 10.60.0.10 40000 10.50.0.30 1433 | ALLOW (source rule DMZ_IN#1) |
| ORC-0001 | oracle | outside:in | packet-tracer input outside tcp 203.0.113.2 65535 10.60.0.10 443 | ALLOW (source rule OUTSIDE_IN#5) |
| ORC-0002 | oracle | outside:in | packet-tracer input outside tcp 203.0.113.2 65535 10.60.0.10 65535 | DROP (source rule OUTSIDE_IN#7) |
| ORC-0004 | oracle | partner:in | packet-tracer input partner tcp 192.0.2.10 40000 203.0.113.1 443 | ALLOW (source rule PARTNER_IN#3) |

### Checks that need another method

| ID | Origin | Context | Flow | Expected result | Why |
|---|---|---|---|---|---|
| ORC-0003 | oracle | outside:in | tcp 203.0.113.2:65535 -> 203.0.113.2:65535 | deny by rule implicit-deny; ledger LED-0002 | traffic to the device itself follows the interface management profile |
| ORC-0005 | oracle | partner:in | tcp 203.0.113.2:65535 -> 203.0.113.2:65535 | deny by rule implicit-deny; ledger LED-0008 | traffic to the device itself follows the interface management profile |

### Rollback (P9)

The change owner decides within 30 minutes of a trigger. Triggers:

- A verification command gives a result that differs from its expected result.
- A P1 or P2 incident that is attributed to the change.
- An application owner asks for a rollback and the change owner agrees.

| Done | ID | Step |
|---|---|---|
| [ ] | RB-01 | Stop further changes on the target and note the time and trigger. |
| [ ] | RB-02 | Re-cable or re-route traffic back to the source. Keep the source configured and powered until the end of hypercare. |
| [ ] | RB-03 | If the target must be reverted, restore its configuration backup from PRE-01 and commit. |
| [ ] | RB-04 | Repeat the source checks to confirm it behaves as before. |
| [ ] | RB-05 | Record the outcome on the change record and inform the CAB. |

### Post-checks and hypercare (P8, P11)

| Done | ID | Step |
|---|---|---|
| [ ] | POST-01 | Watch deny logs on the target for 10 business days and investigate each unexpected deny. |
| [ ] | POST-02 | Review rule hit counts for the rules in the watch list. |
| [ ] | POST-03 | Collect sign-off from the application owner of each zone pair in the matrix. |
| [ ] | POST-04 | Confirm that no unexplained denies remain after hypercare. |
| [ ] | POST-05 | Decommission the source: remove it from production, archive its configuration per the retention policy, update the CMDB and IPAM, and record the decommission. |
| [ ] | POST-06 | Rotate every shared secret that was on the source (3 redacted in this report). Consider them exposed. |

Hypercare lasts 10 business days. Rules and entries to watch:

| Subject | Reason |
|---|---|
| ledger LED-0001 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source permits these flows and the profile admits them.. Affected: tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 23; tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 22; udp 10.50.0.0/24 -> 10.50.0.1/32 dport 161 |
| ledger LED-0002 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: tcp 0.0.0.0/5 and 23 more -> 10.50.0.1/32 and 3 more; tcp 10.50.0.0/24 -> 10.60.0.1/32 and 2 more; tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 0-21,24-65535; and 5 more |
| ledger LED-0003 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source permits these flows and the profile admits them.. Affected: tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 23; tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 22; udp 10.50.0.0/24 -> 10.50.0.1/32 dport 161 |
| ledger LED-0004 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: tcp 0.0.0.0/5 and 23 more -> 10.50.0.1/32 and 3 more; tcp 10.50.0.0/24 -> 10.60.0.1/32 and 2 more; tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 0-21,24-65535; and 5 more |
| ledger LED-0005 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source permits these flows and the profile admits them.. Affected: tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 23; tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 22; udp 10.50.0.0/24 -> 10.50.0.1/32 dport 161 |
| ledger LED-0006 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: tcp 0.0.0.0/5 and 23 more -> 10.50.0.1/32 and 3 more; tcp 10.50.0.0/24 -> 10.60.0.1/32 and 2 more; tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 0-21,24-65535; and 5 more |
| ledger LED-0007 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source permits these flows and the profile admits them.. Affected: tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 23; tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 22; udp 10.50.0.0/24 -> 10.50.0.1/32 dport 161 |
| ledger LED-0008 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: tcp 0.0.0.0/5 and 23 more -> 10.50.0.1/32 and 3 more; tcp 10.50.0.0/24 -> 10.60.0.1/32 and 2 more; tcp 10.50.0.0/24 -> 10.50.0.1/32 dport 0-21,24-65535; and 5 more |
