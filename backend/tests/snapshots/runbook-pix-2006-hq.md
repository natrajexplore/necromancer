# Runbook

## 9. Runbook

### Pre-cutover checks (P6)

| Done | ID | Step |
|---|---|---|
| [ ] | PRE-01 | Back up the running configuration of the source and of the target. Record the file names and SHA-256 values with the change record. |
| [ ] | PRE-02 | Load the candidate on the target in configure mode, run validate full, and do not commit. Attach the output. |
| [ ] | PRE-ZONE-01 | Zone outside: replace the placeholder port ethernet1/1 with the real port for source interface ethernet0 (nameif outside, 198.51.100.1/28). |
| [ ] | PRE-ZONE-02 | Zone inside: replace the placeholder port ethernet1/2 with the real port for source interface ethernet1 (nameif inside, 10.10.0.1/16). |
| [ ] | PRE-ZONE-03 | Zone dmz: replace the placeholder port ethernet1/3 with the real port for source interface ethernet2 (nameif dmz, 192.168.50.1/24). |
| [ ] | PRE-03 | Compare the 1 static routes of the candidate with show route on the source. Dynamic routing is not migrated; configure and review it separately. |
| [ ] | PRE-04 | Review NAT: the candidate carries 6 translations from the source. Dynamic NAT, PAT and other forms are configured and reviewed separately. |
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
| [ ] | CUT-03 | Run the 25 target verification commands and record each result next to its expected result. |
| [ ] | CUT-05 | Test the 2 manual checks by another method and record the result. |
| [ ] | CUT-06 | Compare every result with its expected decision. A mismatch is a rollback trigger. |
| [ ] | CUT-07 | Move traffic to the target as the change plan says. |

### Verification commands on the target (PAN-OS)

Run each command in operational mode on the target after the commit. Each one is followed by the result it must give. Golden flows come first, then one oracle flow for every pair of source rule and candidate rule.

| ID | Origin | Context | Command | Expected result |
|---|---|---|---|---|
| PIX-01 | golden | outside:in | test security-policy-match from outside to dmz source 203.0.113.7 destination 192.168.50.10 destination-port 80 protocol 6 | allow by rule outside_in-1 |
| PIX-02 | golden | outside:in | test security-policy-match from outside to dmz source 198.51.100.20 destination 192.168.50.11 destination-port 443 protocol 6 | allow by rule outside_in-1 |
| PIX-03 | golden | outside:in | test security-policy-match from outside to dmz source 198.51.100.20 destination 192.168.50.11 destination-port 25 protocol 6 | allow by rule outside_in-2 |
| PIX-04 | golden | outside:in | test security-policy-match from outside to dmz source 198.51.100.20 destination 192.168.50.12 destination-port 25 protocol 6 | deny by rule outside_in-7 |
| PIX-05 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.33 destination 192.168.50.12 destination-port 53 protocol 17 | allow by rule outside_in-3 |
| PIX-06 | golden | outside:in | test security-policy-match from outside to dmz source 203.0.113.0 destination 192.168.50.10 destination-port 23 protocol 6 | allow by rule outside_in-5 |
| PIX-07 | golden | outside:in | test security-policy-match from outside to dmz source 203.0.113.255 destination 192.168.50.10 destination-port 23 protocol 6 | allow by rule outside_in-5 |
| PIX-08 | golden | outside:in | test security-policy-match from outside to dmz source 198.51.100.9 destination 192.168.50.10 destination-port 23 protocol 6 | deny by rule outside_in-7 |
| PIX-09 | golden | outside:in | test security-policy-match from outside to dmz source 203.0.113.7 destination 192.168.50.10 destination-port 79 protocol 6 | deny by rule outside_in-7 |
| PIX-10 | golden | outside:in | test security-policy-match from outside to dmz source 203.0.113.7 destination 192.168.50.10 destination-port 81 protocol 6 | deny by rule outside_in-7 |
| PIX-11 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.1 destination 192.168.50.10 protocol 1 application necro-icmp-0 | allow by rule outside_in-6 (ICMP type 0) |
| PIX-12 | golden | outside:in | test security-policy-match from outside to dmz source 192.0.2.1 destination 192.168.50.10 protocol 1 | deny by rule outside_in-7 (ICMP type 8) |
| PIX-13 | golden | dmz:in | test security-policy-match from dmz to outside source 192.168.50.12 destination 198.51.100.53 destination-port 53 protocol 17 | allow by rule dmz_in-1 |
| PIX-14 | golden | dmz:in | test security-policy-match from dmz to inside source 192.168.50.20 destination 10.10.10.5 destination-port 22 protocol 6 | allow by rule dmz_in-3 |
| PIX-15 | golden | inside:in | test security-policy-match from inside to outside source 10.10.20.5 destination 198.51.100.200 destination-port 443 protocol 6 | allow by rule implicit-inside-to-outside |
| PIX-16 | golden | inside:in | test security-policy-match from inside to dmz source 10.10.20.5 destination 192.168.50.12 destination-port 53 protocol 17 | allow by rule implicit-inside-to-dmz |
| ORC-0001 | oracle | outside:in | test security-policy-match from outside to dmz source 192.168.50.0 destination 192.168.50.11 destination-port 443 protocol 6 | allow by rule outside_in-1 |
| ORC-0002 | oracle | outside:in | test security-policy-match from outside to dmz source 192.168.50.0 destination 192.168.50.11 destination-port 25 protocol 6 | allow by rule outside_in-2 |
| ORC-0003 | oracle | outside:in | test security-policy-match from outside to dmz source 192.168.50.0 destination 192.168.50.12 destination-port 53 protocol 17 | allow by rule outside_in-3 |
| ORC-0004 | oracle | outside:in | test security-policy-match from outside to outside source 192.0.2.10 destination 198.51.100.2 protocol 1 | deny by rule outside_in-7 (ICMP type 0) |
| ORC-0005 | oracle | outside:in | test security-policy-match from outside to dmz source 192.168.50.0 destination 192.168.50.0 protocol 1 application necro-icmp-0 | allow by rule outside_in-6 (ICMP type 0) |
| ORC-0008 | oracle | outside:in | test security-policy-match from outside to dmz source 192.168.50.0 destination 192.168.50.0 destination-port 65535 protocol 6 | deny by rule outside_in-7 |
| ORC-0009 | oracle | dmz:in | test security-policy-match from dmz to inside source 192.168.50.12 destination 10.10.0.0 destination-port 53 protocol 17 | allow by rule dmz_in-1 |
| ORC-0010 | oracle | dmz:in | test security-policy-match from dmz to inside source 192.168.50.11 destination 10.10.0.0 destination-port 25 protocol 6 | allow by rule dmz_in-2 |
| ORC-0011 | oracle | dmz:in | test security-policy-match from dmz to inside source 10.10.0.0 destination 10.10.0.0 destination-port 65535 protocol 6 | allow by rule dmz_in-3 |

### Verification commands on the source (ASA packet-tracer)

packet-tracer is not available on PIX 6.3(5) (it needs ASA 7.2 or later), so no source commands are listed. The expected decisions of the source are evidenced by the equivalence proof and the golden flows.

### Checks that need another method

| ID | Origin | Context | Flow | Expected result | Why |
|---|---|---|---|---|---|
| ORC-0006 | oracle | outside:in | icmp 192.168.50.0 -> 198.51.100.1 type 0 | allow by rule mgmt-profile:ping; ledger LED-0001 | traffic to the device itself follows the interface management profile |
| ORC-0007 | oracle | outside:in | icmp 192.168.50.0 -> 10.10.0.1 type 0 | deny by rule implicit-deny; ledger LED-0002 | traffic to the device itself follows the interface management profile |

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
| ledger LED-0001 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source permits these flows and the profile admits them.. Affected: icmp any -> 198.51.100.1/32 |
| ledger LED-0002 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source denies these flows and the profile does not admit them.. Affected: tcp any -> 10.10.0.1/32 and 2 more; udp any -> 10.10.0.1/32 and 2 more; icmp any -> 10.10.0.1/32 and 1 more; and 1 more |
| ledger LED-0003 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source permits these flows and the profile admits them.. Affected: tcp 10.10.0.0/16 -> 10.10.0.1/32 dport 23 |
| ledger LED-0004 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: icmp any -> 10.10.0.1/32 |
| ledger LED-0005 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source denies these flows and the profile does not admit them.. Affected: tcp 0.0.0.0/5 and 15 more -> 10.10.0.1/32 and 2 more; tcp 10.10.0.0/16 -> 192.168.50.1/32 and 1 more; tcp 10.10.0.0/16 -> 10.10.0.1/32 dport 0-22,24-65535; and 3 more |
| ledger LED-0006 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source permits these flows and the profile admits them.. Affected: icmp any -> 192.168.50.1/32 |
| ledger LED-0007 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source denies these flows and the profile does not admit them.. Affected: tcp any -> 10.10.0.1/32 and 2 more; udp any -> 10.10.0.1/32 and 2 more; icmp any -> 10.10.0.1/32 and 1 more; and 1 more |
| source rule outside_in#4 | not exercised by the proof in context outside:in (85.7% of active rules hit) |
| candidate rule outside_in-4 | not exercised by the proof in context outside:in (75% of active rules hit) |
| candidate rule necro-final-deny | not exercised by the proof in context outside:in (75% of active rules hit) |
| source rule dmz_in#4 | not exercised by the proof in context dmz:in (75% of active rules hit) |
| candidate rule dmz_in-4 | not exercised by the proof in context dmz:in (60% of active rules hit) |
| candidate rule necro-final-deny | not exercised by the proof in context dmz:in (60% of active rules hit) |
