# Runbook

## 9. Runbook

### Pre-cutover checks (P6)

| Done | ID | Step |
|---|---|---|
| [ ] | PRE-01 | Back up the running configuration of the source and of the target. Record the file names and SHA-256 values with the change record. |
| [ ] | PRE-02 | Load the candidate on the target in configure mode, run validate full, and do not commit. Attach the output. |
| [ ] | PRE-ZONE-01 | Zone WAN: replace the placeholder port ethernet1/1 with the real port for source interface FastEthernet0/0 (nameif WAN, 192.0.2.2/30). |
| [ ] | PRE-ZONE-02 | Zone LAN: replace the placeholder port ethernet1/2 with the real port for source interface FastEthernet0/1 (nameif LAN, 10.20.0.1/16). |
| [ ] | PRE-ZONE-03 | Zone MGMT: replace the placeholder port ethernet1/3 with the real port for source interface FastEthernet0/2 (nameif MGMT, 10.99.0.1/24). |
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
| [ ] | CUT-03 | Run the 22 target verification commands and record each result next to its expected result. |
| [ ] | CUT-05 | Test the 11 manual checks by another method and record the result. |
| [ ] | CUT-06 | Compare every result with its expected decision. A mismatch is a rollback trigger. |
| [ ] | CUT-07 | Move traffic to the target as the change plan says. |

### Verification commands on the target (PAN-OS)

Run each command in operational mode on the target after the commit. Each one is followed by the result it must give. Golden flows come first, then one oracle flow for every pair of source rule and candidate rule.

| ID | Origin | Context | Command | Expected result |
|---|---|---|---|---|
| IOS-01 | golden | FastEthernet0/0:in | test security-policy-match from WAN to LAN source 198.51.100.5 destination 10.20.3.4 destination-port 51000 protocol 6 | deny by rule 110-7; ledger LED-0001 |
| IOS-02 | golden | FastEthernet0/0:in | test security-policy-match from WAN to LAN source 198.51.100.5 destination 10.20.3.4 destination-port 51000 protocol 6 | deny by rule 110-7 |
| IOS-03 | golden | FastEthernet0/0:in | test security-policy-match from WAN to LAN source 198.51.100.5 destination 10.20.1.10 destination-port 443 protocol 6 | allow by rule 110-2 |
| IOS-05 | golden | FastEthernet0/0:in | test security-policy-match from WAN to LAN source 192.0.2.1 destination 10.20.3.4 protocol 1 application necro-icmp-0 | allow by rule 110-5 (ICMP type 0) |
| IOS-06 | golden | FastEthernet0/0:in | test security-policy-match from WAN to LAN source 192.0.2.1 destination 10.20.3.4 protocol 1 | deny by rule 110-7 (ICMP type 8) |
| IOS-07 | golden | FastEthernet0/0:in | test security-policy-match from WAN to LAN source 192.0.2.1 destination 10.20.3.4 protocol 1 application necro-icmp-11 | allow by rule 110-6 (ICMP type 11) |
| IOS-08 | golden | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 10.20.5.9 destination 203.0.113.80 destination-port 443 protocol 6 | allow by rule LAN_OUT-2 |
| IOS-09 | golden | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 10.20.5.9 destination 203.0.113.80 destination-port 6010 protocol 6 | allow by rule LAN_OUT-5 |
| IOS-10 | golden | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 10.20.5.9 destination 203.0.113.80 destination-port 6011 protocol 6 | deny by rule LAN_OUT-6 |
| IOS-11 | golden | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 10.20.5.9 destination 203.0.113.80 destination-port 5999 protocol 6 | deny by rule LAN_OUT-6 |
| IOS-12 | golden | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 10.20.1.1 destination 203.0.113.53 destination-port 53 protocol 6 | deny by rule LAN_OUT-6 |
| IOS-13 | golden | FastEthernet0/2:in | test security-policy-match from MGMT to LAN source 10.99.0.50 destination 10.20.1.10 destination-port 3389 protocol 6 | allow by rule implicit-MGMT-to-any |
| ORC-0001 | oracle | FastEthernet0/0:in | test security-policy-match from WAN to LAN source 192.0.2.2 destination 10.20.255.255 destination-port 65535 protocol 6 | deny by rule 110-7; ledger LED-0001 |
| ORC-0003 | oracle | FastEthernet0/0:in | test security-policy-match from WAN to LAN source 192.0.2.2 destination 10.20.1.10 destination-port 443 protocol 6 | allow by rule 110-2 |
| ORC-0004 | oracle | FastEthernet0/0:in | test security-policy-match from WAN to LAN source 192.0.2.2 destination 10.20.1.53 destination-port 53 protocol 17 | allow by rule 110-3 |
| ORC-0006 | oracle | FastEthernet0/0:in | test security-policy-match from WAN to WAN source 192.0.2.10 destination 192.0.2.1 protocol 1 application necro-icmp-0 | allow by rule 110-5 (ICMP type 0) |
| ORC-0008 | oracle | FastEthernet0/0:in | test security-policy-match from WAN to WAN source 192.0.2.10 destination 192.0.2.1 protocol 1 application necro-icmp-11 | allow by rule 110-6 (ICMP type 11) |
| ORC-0011 | oracle | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 10.20.0.0 destination 192.0.2.1 destination-port 80 protocol 6 | allow by rule LAN_OUT-1 |
| ORC-0013 | oracle | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 10.20.0.0 destination 192.0.2.1 destination-port 443 protocol 6 | allow by rule LAN_OUT-2 |
| ORC-0015 | oracle | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 10.20.0.0 destination 192.0.2.1 destination-port 53 protocol 17 | allow by rule LAN_OUT-3 |
| ORC-0017 | oracle | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 10.20.0.0 destination 192.0.2.1 destination-port 6000 protocol 6 | allow by rule LAN_OUT-5 |
| ORC-0019 | oracle | FastEthernet0/1:in | test security-policy-match from LAN to WAN source 192.0.2.10 destination 192.0.2.1 destination-port 443 protocol 6 | deny by rule LAN_OUT-6 |

### Verification commands on the source (ASA packet-tracer)

packet-tracer is not available on IOS 12.4 (it needs ASA 7.2 or later), so no source commands are listed. The expected decisions of the source are evidenced by the equivalence proof and the golden flows.

### Checks that need another method

| ID | Origin | Context | Flow | Expected result | Why |
|---|---|---|---|---|---|
| IOS-04 | golden | FastEthernet0/0:in | tcp 198.51.100.5:40000 -> 10.20.0.1:23 | deny by rule implicit-deny; ledger LED-0002 | traffic to the device itself follows the interface management profile |
| ORC-0002 | oracle | FastEthernet0/0:in | tcp 192.0.2.2:65535 -> 10.20.0.1:65535 | deny by rule implicit-deny; ledger LED-0002 | traffic to the device itself follows the interface management profile |
| ORC-0005 | oracle | FastEthernet0/0:in | tcp 192.0.2.2:65535 -> 10.20.0.1:23 | deny by rule implicit-deny; ledger LED-0002 | traffic to the device itself follows the interface management profile |
| ORC-0007 | oracle | FastEthernet0/0:in | icmp 192.0.2.2 -> 192.0.2.2 type 0 | deny by rule implicit-deny; ledger LED-0002 | traffic to the device itself follows the interface management profile |
| ORC-0009 | oracle | FastEthernet0/0:in | icmp 192.0.2.2 -> 192.0.2.2 type 11 | deny by rule implicit-deny; ledger LED-0002 | traffic to the device itself follows the interface management profile |
| ORC-0010 | oracle | FastEthernet0/0:in | tcp 192.0.2.2:65535 -> 192.0.2.2:65535 | deny by rule implicit-deny; ledger LED-0004 | traffic to the device itself follows the interface management profile |
| ORC-0012 | oracle | FastEthernet0/1:in | tcp 10.20.255.255:65535 -> 192.0.2.2:80 | deny by rule implicit-deny; ledger LED-0005 | traffic to the device itself follows the interface management profile |
| ORC-0014 | oracle | FastEthernet0/1:in | tcp 10.20.255.255:65535 -> 192.0.2.2:443 | deny by rule implicit-deny; ledger LED-0005 | traffic to the device itself follows the interface management profile |
| ORC-0016 | oracle | FastEthernet0/1:in | udp 10.20.255.255:65535 -> 192.0.2.2:53 | deny by rule implicit-deny; ledger LED-0005 | traffic to the device itself follows the interface management profile |
| ORC-0018 | oracle | FastEthernet0/1:in | tcp 10.20.255.255:65535 -> 192.0.2.2:6010 | deny by rule implicit-deny; ledger LED-0005 | traffic to the device itself follows the interface management profile |
| ORC-0020 | oracle | FastEthernet0/1:in | tcp 192.0.2.2:65535 -> 192.0.2.2:65535 | deny by rule implicit-deny; ledger LED-0007 | traffic to the device itself follows the interface management profile |

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
| [ ] | POST-06 | Rotate every shared secret that was on the source (4 redacted in this report). Consider them exposed. |

Hypercare lasts 10 business days. Rules and entries to watch:

| Subject | Reason |
|---|---|
| ledger LED-0001 (stateful-established) | 110#1 matches only TCP segments with ACK or RST set. PAN-OS has no equivalent, so the rule is omitted and the flows it decided fall to the rules after it (deny for these).. Affected: tcp any -> 10.20.0.0/32 and 22 more established; tcp any -> 10.20.1.10/32 dport 0-442,444-65535 established |
| ledger LED-0002 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: tcp any -> 10.20.0.1/32 established; tcp any -> 10.20.0.1/32 dport 23; icmp any -> 10.20.0.1/32 and 2 more type 0; and 1 more |
| ledger LED-0003 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. A profile has one permitted-ip list for all its services, so it admits flows the source denied (a service from a source that only another service allowed).. Affected: tcp 10.99.0.0/24 -> 192.0.2.2/32 dport 23; tcp 10.99.0.0/24 -> 192.0.2.2/32 dport 22; udp 10.99.0.0/24 -> 192.0.2.2/32 dport 161 |
| ledger LED-0004 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source denies these flows and the profile does not admit them.. Affected: tcp 0.0.0.0/5 and 23 more -> 10.99.0.1/32 and 1 more; tcp 10.99.0.0/24 -> 10.99.0.1/32; tcp 10.99.0.0/24 -> 192.0.2.2/32 dport 0-21,24-65535; and 6 more |
| ledger LED-0005 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: tcp 10.20.0.0/16 -> 10.20.0.1/32 and 2 more dport 80; tcp 10.20.0.0/16 -> 10.20.0.1/32 and 2 more dport 443; udp 10.20.0.0/16 -> 10.20.0.1/32 and 2 more dport 53; and 1 more |
| ledger LED-0006 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. A profile has one permitted-ip list for all its services, so it admits flows the source denied (a service from a source that only another service allowed).. Affected: tcp 0.0.0.0/5 and 15 more -> 10.20.0.1/32 dport 23; tcp 0.0.0.0/5 and 15 more -> 10.20.0.1/32 dport 22; tcp 10.20.0.0/16 -> 10.20.0.1/32 dport 23; and 3 more |
| ledger LED-0007 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source denies these flows and the profile does not admit them.. Affected: tcp 0.0.0.0/5 and 15 more -> 10.99.0.1/32 and 1 more; tcp 0.0.0.0/5 and 15 more -> 10.20.0.1/32 dport 0-21,24-65535; tcp 10.20.0.0/16 -> 10.99.0.1/32 and 1 more dport 0-79,81-442,444-5999,6011-65535; and 7 more |
| ledger LED-0008 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source permits these flows and the profile admits them.. Affected: tcp 10.99.0.0/24 -> 10.99.0.1/32 dport 23; tcp 10.99.0.0/24 -> 10.99.0.1/32 dport 22; udp 10.99.0.0/24 -> 10.99.0.1/32 dport 161 |
| ledger LED-0009 (to-the-box) | Traffic to the device's own addresses is governed by the interface management profile. The source model permits these flows but no management service of the emitted profile admits them, so PAN-OS denies them.. Affected: tcp 0.0.0.0/5 and 23 more -> 10.20.0.1/32 and 2 more; tcp 10.99.0.0/24 -> 10.20.0.1/32 and 1 more; tcp 10.99.0.0/24 -> 10.99.0.1/32 dport 0-21,24-65535; and 5 more |
| candidate rule 110-4 | not exercised by the proof in context FastEthernet0/0:in (71.4% of active rules hit) |
| candidate rule necro-final-deny | not exercised by the proof in context FastEthernet0/0:in (71.4% of active rules hit) |
| source rule LAN_OUT#4 | not exercised by the proof in context FastEthernet0/1:in (83.3% of active rules hit) |
| candidate rule LAN_OUT-4 | not exercised by the proof in context FastEthernet0/1:in (71.4% of active rules hit) |
| candidate rule necro-final-deny | not exercised by the proof in context FastEthernet0/1:in (71.4% of active rules hit) |
| candidate rule necro-final-deny | not exercised by the proof in context FastEthernet0/2:in (50% of active rules hit) |
