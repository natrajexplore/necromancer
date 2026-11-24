# Runbook

## 9. Runbook

### Pre-cutover checks (P6)

| Done | ID | Step |
|---|---|---|
| [ ] | PRE-01 | Back up the running configuration of the source and of the target. Record the file names and SHA-256 values with the change record. |
| [ ] | PRE-02 | Load the candidate on the target in configure mode, run validate full, and do not commit. Attach the output. |
| [ ] | PRE-ZONE-01 | Zone outside: replace the placeholder port ethernet1/1 with the real port for source interface Ethernet0/0 (nameif outside, 198.51.100.2/29). |
| [ ] | PRE-ZONE-02 | Zone inside: replace the placeholder port ethernet1/2 with the real port for source interface Ethernet0/1 (nameif inside, 172.16.10.1/24). |
| [ ] | PRE-03 | Compare the 2 static routes of the candidate with show route on the source. Dynamic routing is not migrated; configure and review it separately. |
| [ ] | PRE-04 | Review NAT: the candidate carries 1 translations from the source. Dynamic NAT, PAT and other forms are configured and reviewed separately. |
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
| [ ] | CUT-03 | Run the 23 target verification commands and record each result next to its expected result. |
| [ ] | CUT-04 | Run the 23 source packet-tracer commands and record each result. |
| [ ] | CUT-05 | Test the 2 manual checks by another method and record the result. |
| [ ] | CUT-06 | Compare every result with its expected decision. A mismatch is a rollback trigger. |
| [ ] | CUT-07 | Move traffic to the target as the change plan says. |

### Verification commands on the target (PAN-OS)

Run each command in operational mode on the target after the commit. Each one is followed by the result it must give. Golden flows come first, then one oracle flow for every pair of source rule and candidate rule.

| ID | Origin | Context | Command | Expected result |
|---|---|---|---|---|
| A82-01 | golden | outside:in | test security-policy-match from outside to inside source 203.0.113.200 destination 172.16.20.10 destination-port 8085 protocol 6 | allow by rule OUTSIDE_IN-1 |
| A82-02 | golden | outside:in | test security-policy-match from outside to inside source 203.0.113.127 destination 172.16.20.10 destination-port 8085 protocol 6 | allow by rule OUTSIDE_IN-6 |
| A82-03 | golden | outside:in | test security-policy-match from outside to inside source 203.0.113.50 destination 172.16.30.5 destination-port 1521 protocol 6 | allow by rule OUTSIDE_IN-2 |
| A82-04 | golden | outside:in | test security-policy-match from outside to inside source 203.0.113.50 destination 172.16.20.7 destination-port 8443 protocol 6 | allow by rule OUTSIDE_IN-3 |
| A82-05 | golden | outside:in | test security-policy-match from outside to inside source 203.0.113.50 destination 172.16.30.5 destination-port 8443 protocol 6 | allow by rule OUTSIDE_IN-4 |
| A82-06 | golden | outside:in | test security-policy-match from outside to inside source 198.51.100.77 destination 172.16.30.5 destination-port 161 protocol 17 | allow by rule OUTSIDE_IN-5 |
| A82-07 | golden | outside:in | test security-policy-match from outside to inside source 198.51.100.77 destination 172.16.30.5 destination-port 162 protocol 17 | deny by rule OUTSIDE_IN-9 |
| A82-08 | golden | outside:in | test security-policy-match from outside to inside source 192.0.2.10 destination 172.16.20.10 destination-port 22 protocol 6 | deny by rule OUTSIDE_IN-9 |
| A82-09 | golden | outside:in | test security-policy-match from outside to inside source 192.0.2.10 destination 172.16.20.10 destination-port 21 protocol 6 | allow by rule OUTSIDE_IN-6 |
| A82-10 | golden | outside:in | test security-policy-match from outside to inside source 203.0.113.200 destination 198.51.100.5 destination-port 1433 protocol 6 | allow by rule OUTSIDE_IN-7 |
| A82-11 | golden | outside:in | test security-policy-match from outside to inside source 192.0.2.10 destination 172.16.30.5 destination-port 3389 protocol 6 | deny by rule OUTSIDE_IN-9 |
| A82-12 | golden | inside:in | test security-policy-match from inside to outside source 172.16.10.20 destination 192.0.2.53 destination-port 53 protocol 17 | allow by rule INSIDE_OUT-3 |
| A82-13 | golden | inside:in | test security-policy-match from inside to outside source 172.16.10.20 destination 192.0.2.1 destination-port 3389 protocol 6 | allow by rule INSIDE_OUT-4 |
| ORC-0001 | oracle | outside:in | test security-policy-match from outside to inside source 203.0.113.255 destination 172.16.20.255 destination-port 8443 protocol 6 | allow by rule OUTSIDE_IN-1 |
| ORC-0002 | oracle | outside:in | test security-policy-match from outside to inside source 203.0.113.50 destination 172.16.20.255 destination-port 8443 protocol 6 | allow by rule OUTSIDE_IN-3 |
| ORC-0003 | oracle | outside:in | test security-policy-match from outside to inside source 198.51.100.255 destination 172.16.30.5 destination-port 161 protocol 17 | allow by rule OUTSIDE_IN-5 |
| ORC-0004 | oracle | outside:in | test security-policy-match from outside to inside source 198.51.100.5 destination 172.16.20.255 destination-port 65535 protocol 6 | allow by rule OUTSIDE_IN-6 |
| ORC-0005 | oracle | outside:in | test security-policy-match from outside to inside source 203.0.113.255 destination 198.51.100.5 destination-port 1433 protocol 6 | allow by rule OUTSIDE_IN-7 |
| ORC-0006 | oracle | outside:in | test security-policy-match from outside to inside source 198.51.100.5 destination 198.51.100.5 destination-port 65535 protocol 6 | deny by rule OUTSIDE_IN-9 |
| ORC-0008 | oracle | inside:in | test security-policy-match from inside to inside source 172.16.10.255 destination 172.16.30.5 destination-port 80 protocol 6 | allow by rule INSIDE_OUT-1 |
| ORC-0010 | oracle | inside:in | test security-policy-match from inside to inside source 172.16.10.255 destination 172.16.30.5 destination-port 443 protocol 6 | allow by rule INSIDE_OUT-2 |
| ORC-0011 | oracle | inside:in | test security-policy-match from inside to inside source 172.16.10.255 destination 172.16.30.5 destination-port 53 protocol 17 | allow by rule INSIDE_OUT-3 |
| ORC-0012 | oracle | inside:in | test security-policy-match from inside to inside source 172.16.30.5 destination 172.16.30.5 destination-port 65535 protocol 6 | allow by rule INSIDE_OUT-4 |

### Verification commands on the source (ASA packet-tracer)

Run these on the source before the freeze ends, to compare with the baseline. packet-tracer exists from ASA 7.2.

| ID | Origin | Context | Command | Expected result |
|---|---|---|---|---|
| A82-01 | golden | outside:in | packet-tracer input outside tcp 203.0.113.200 40000 172.16.20.10 8085 | ALLOW (source rule OUTSIDE_IN#1) |
| A82-02 | golden | outside:in | packet-tracer input outside tcp 203.0.113.127 40000 172.16.20.10 8085 | ALLOW (source rule OUTSIDE_IN#6) |
| A82-03 | golden | outside:in | packet-tracer input outside tcp 203.0.113.50 40000 172.16.30.5 1521 | ALLOW (source rule OUTSIDE_IN#2) |
| A82-04 | golden | outside:in | packet-tracer input outside tcp 203.0.113.50 40000 172.16.20.7 8443 | ALLOW (source rule OUTSIDE_IN#3) |
| A82-05 | golden | outside:in | packet-tracer input outside tcp 203.0.113.50 40000 172.16.30.5 8443 | ALLOW (source rule OUTSIDE_IN#4) |
| A82-06 | golden | outside:in | packet-tracer input outside udp 198.51.100.77 50000 172.16.30.5 161 | ALLOW (source rule OUTSIDE_IN#5) |
| A82-07 | golden | outside:in | packet-tracer input outside udp 198.51.100.77 50000 172.16.30.5 162 | DROP (source rule OUTSIDE_IN#9) |
| A82-08 | golden | outside:in | packet-tracer input outside tcp 192.0.2.10 40000 172.16.20.10 22 | DROP (source rule OUTSIDE_IN#9) |
| A82-09 | golden | outside:in | packet-tracer input outside tcp 192.0.2.10 40000 172.16.20.10 21 | ALLOW (source rule OUTSIDE_IN#6) |
| A82-10 | golden | outside:in | packet-tracer input outside tcp 203.0.113.200 40000 198.51.100.5 1433 | ALLOW (source rule OUTSIDE_IN#7) |
| A82-11 | golden | outside:in | packet-tracer input outside tcp 192.0.2.10 40000 172.16.30.5 3389 | DROP (source rule OUTSIDE_IN#9) |
| A82-12 | golden | inside:in | packet-tracer input inside udp 172.16.10.20 50000 192.0.2.53 53 | ALLOW (source rule INSIDE_OUT#3) |
| A82-13 | golden | inside:in | packet-tracer input inside tcp 172.16.10.20 50000 192.0.2.1 3389 | ALLOW (source rule INSIDE_OUT#4) |
| ORC-0001 | oracle | outside:in | packet-tracer input outside tcp 203.0.113.255 65535 172.16.20.255 8443 | ALLOW (source rule OUTSIDE_IN#1) |
| ORC-0002 | oracle | outside:in | packet-tracer input outside tcp 203.0.113.50 65535 172.16.20.255 8443 | ALLOW (source rule OUTSIDE_IN#3) |
| ORC-0003 | oracle | outside:in | packet-tracer input outside udp 198.51.100.255 65535 172.16.30.5 161 | ALLOW (source rule OUTSIDE_IN#5) |
| ORC-0004 | oracle | outside:in | packet-tracer input outside tcp 198.51.100.5 65535 172.16.20.255 65535 | ALLOW (source rule OUTSIDE_IN#6) |
| ORC-0005 | oracle | outside:in | packet-tracer input outside tcp 203.0.113.255 65535 198.51.100.5 1433 | ALLOW (source rule OUTSIDE_IN#7) |
| ORC-0006 | oracle | outside:in | packet-tracer input outside tcp 198.51.100.5 65535 198.51.100.5 65535 | DROP (source rule OUTSIDE_IN#9) |
| ORC-0008 | oracle | inside:in | packet-tracer input inside tcp 172.16.10.255 65535 172.16.30.5 80 | ALLOW (source rule INSIDE_OUT#1) |
| ORC-0010 | oracle | inside:in | packet-tracer input inside tcp 172.16.10.255 65535 172.16.30.5 443 | ALLOW (source rule INSIDE_OUT#2) |
| ORC-0011 | oracle | inside:in | packet-tracer input inside udp 172.16.10.255 65535 172.16.30.5 53 | ALLOW (source rule INSIDE_OUT#3) |
| ORC-0012 | oracle | inside:in | packet-tracer input inside tcp 172.16.30.5 65535 172.16.30.5 65535 | ALLOW (source rule INSIDE_OUT#4) |

### Checks that need another method

| ID | Origin | Context | Flow | Expected result | Why |
|---|---|---|---|---|---|
| ORC-0007 | oracle | outside:in | tcp 198.51.100.5:65535 -> 198.51.100.2:65535 | deny by rule implicit-deny; ledger LED-0001 | traffic to the device itself follows the interface management profile |
| ORC-0009 | oracle | inside:in | tcp 172.16.10.255:65535 -> 198.51.100.2:80 | deny by rule implicit-deny; ledger LED-0002 | traffic to the device itself follows the interface management profile |

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
| [ ] | POST-06 | Rotate every shared secret that was on the source (2 redacted in this report). Consider them exposed. |

Hypercare lasts 10 business days. Rules and entries to watch:

| Subject | Reason |
|---|---|
| ledger LED-0001 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: tcp any -> 172.16.10.1/32 and 1 more; udp any -> 172.16.10.1/32 and 1 more; icmp any -> 172.16.10.1/32 and 1 more; and 1 more |
| ledger LED-0002 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: tcp any -> 172.16.10.1/32 and 1 more; udp any -> 172.16.10.1/32 and 1 more; icmp any -> 172.16.10.1/32 and 1 more; and 1 more |
| candidate rule necro-final-deny | not exercised by the proof in context outside:in (88.9% of active rules hit) |
| candidate rule necro-final-deny | not exercised by the proof in context inside:in (80% of active rules hit) |
