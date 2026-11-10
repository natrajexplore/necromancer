---
inclusion: fileMatch
fileMatchPattern: ["backend/necro/**/*.py", "backend/tests/**/*.py", "samples/**/*"]
---

# Firewall policy semantics: these must be exact

These rules define correctness. When in doubt, follow them over intuition. A behaviour that isn't
covered here is **not** guessed: the line becomes an `UnparsedLine(security_relevant=True)` and the
coverage gate blocks until a human waives it (see `migration-governance.md`).

The hand-verified vectors in `samples/golden-flows/*.toml` are the acceptance test for this document.

---

## 0. Vocabulary
- **Context**: one ingress interface's inbound policy, named `<nameif|interface>:in`. Outbound ACLs add an
  egress check to the same flow (see 1.4 and 2.4).
- **Rule id**: `<acl-name>#<seq>`, where `seq` is the 1-based ordinal of the ACE in that ACL **as written**.
  Remarks are not counted. Unsupported ACEs (IPv6, etc.) **are** counted, so ids stay stable.
- **Implicit decisions** use reserved rule ids: `implicit-deny`, `implicit-security-level`,
  `implicit-permit-no-acl`, `same-security-deny`.
- **Address space**: the addresses an ACL is written in. `mapped` (PIX 6.x, ASA ≤ 8.2), `real` (ASA ≥ 8.3), `as-is` (IOS).
- **Security-relevant line**: any line that can change whether a packet is permitted. It must never be silently ignored.

## 1. Cisco PIX 6.x / ASA 7.x–8.2

### 1.1 ACL evaluation
- ACLs are **first-match** with an **implicit `deny ip any any`** after the last ACE.
- `access-group <acl> in interface <nameif>` binds an ACL to ingress. One context per binding.
- `inactive` ACEs stay in the IR (flag set) and are **excluded from evaluation**. PAN-OS emits them as `disabled yes`.
- `log [level] [interval N]` and `log disable` are attributes only. They don't change the decision.
- `time-range NAME`: the IR treats the ACE as **always active** (a superset). The emitter creates a PAN-OS
  schedule object, and a ledger entry of class `time-range` records that the oracle can't model time.
- `remark` text attaches to the **next** ACE as `Rule.remark` and becomes the PAN-OS rule description (≤ 1023 chars).

### 1.2 Interfaces and security levels (implicit behaviour)
- `nameif` (PIX: `nameif <hw> <name> security<N>`; ASA: `nameif` + `security-level` under `interface`).
- **No ACL bound to an interface (and no global ACL)**: traffic entering it is **permitted to lower** security
  levels (`implicit-security-level`) and **denied to higher or equal** levels (`implicit-deny`, or
  `same-security-deny` for equal levels).
- **ACL bound**: the ACL alone decides. Security levels no longer grant anything on that ingress.
- **Equal security levels**: denied even when an ACL permits, unless
  `same-security-traffic permit inter-interface` is set (`same-security-deny`).
  Hairpin traffic (in and out of the same interface) requires `same-security-traffic permit intra-interface`.
- Return traffic of an allowed connection is permitted by state. ACLs don't need return rules.

### 1.3 Traffic to the device itself
ACLs bound with `access-group` do **not** filter traffic addressed to the ASA/PIX's own interface IPs.
To-the-box access is governed by `telnet`, `ssh`, `http`, `icmp` and `snmp-server host` commands. These
go into the management-plane model (`to_zone = "self"`) and map to a PAN-OS **interface management profile**
with permitted IPs, never to security rules. ACLs bound with `control-plane` are management-plane too.

### 1.4 Outbound ACLs
`access-group <acl> out interface <nameif>` is evaluated **after** the ingress decision, on the egress
interface. A flow is permitted only if ingress permits **and** egress permits. On PAN-OS this becomes the
`to` zone of the same rule set. Emit it by intersecting the rules, or record an `outbound-acl` ledger
entry if it can't be expressed exactly.

### 1.5 NAT and address space (the classic migration trap)
- **PIX 6.x** always enforces nat-control: a flow with no matching `nat`/`static`/`nat 0` translation is
  dropped **even if the ACL permits it**. **ASA 7.0–8.2** does this only when `nat-control` is configured.
  The evaluator must model this as `implicit-deny` with reason `no-translation`.
- **Pre-8.3** (`static (real_if,mapped_if) mapped real ...`): ACLs on the mapped side reference the
  **mapped** (global) address.
- **8.3+** (object NAT `nat (real_if,mapped_if) static X` inside `object network`, and twice NAT
  `nat (a,b) source ... destination ...`): ACLs reference the **real** address.
- **PAN-OS** security rules match the **pre-NAT** destination IP and the **post-NAT** destination zone.
  - Pre-8.3 → PAN-OS: keep the ACL address (it's already pre-NAT). Compute the to-zone from the route
    lookup of the **real** address.
  - 8.3+ → PAN-OS: replace the real destination with the **mapped** address for flows arriving on the NAT's
    mapped interface. The to-zone is the real interface. Golden flow `A98-01` pins this down.
- Dynamic NAT/PAT (`nat (inside) 1` + `global`, `dynamic interface`) changes source addresses only. PAN-OS
  security rules use the pre-NAT source, so the source address in the rule doesn't change.
- Unsupported NAT forms (policy NAT with ACLs, twice NAT with service translation, `nat 0 access-list`)
  are security-relevant unparsed lines in v1.

### 1.6 Names and objects
- `names` enables aliases. `name <ip> <label> [description ...]` must be resolved before evaluation.
- `object-group network|service|protocol|icmp-type` can **nest** (`group-object`). Expand them recursively.
  Detect cycles and raise `ParseError` naming the cycle path. An undefined group reference is a `ParseError`.
- `object-group service NAME tcp|udp|tcp-udp` holds `port-object`s and goes in the **port** position.
  `tcp-udp` used in a `udp` ACE yields only the UDP ports. `object-group service NAME` (no protocol)
  holds `service-object`s and goes in the **protocol** position.
- 8.3+: `object network` (`host`, `subnet`, `range`, `fqdn`) and `object service`
  (`service tcp|udp [source op] [destination op]`). `range` becomes the minimal CIDR set. `fqdn` is
  security-relevant unparsed in v1, because the oracle can't resolve it.
- `network-object object X` and `service-object object X` reference objects.

### 1.7 Masks, keywords and operators
- PIX/ASA use **subnet masks** (`255.255.255.0`). IOS uses **wildcard masks** (`0.0.0.255`). Never confuse them.
- `any` = 0.0.0.0/0 for IPv4. `any4` is IPv4-only. `any6`, IPv6 literals and `ipv6 access-list` are
  security-relevant unparsed in v1 (IR v1 is IPv4-only).
- Port operators `eq, neq, lt, gt, range` are inclusive. `neq p` = `[0,p-1] ∪ [p+1,65535]`, `lt p` = `[0,p-1]`,
  `gt p` = `[p+1,65535]`. Source-port operators must be honoured too, not only destination ports.
- Port and ICMP **names are resolved with tables keyed by (protocol, name)**. Never use one flat name→port map
  (see §4).

### 1.8 Out-of-scope modes (detect, then block)
`firewall transparent`, `mode multiple` (security contexts), `conduit` and `outbound` (PIX legacy
commands), identity firewall (`user`, `object-group user`), TrustSec (`security-group`) in ACEs, and
`access-list ... ethertype|webtype` that are bound. Each becomes a security-relevant unparsed line or
sets `Policy.mode`, and the coverage gate blocks.

## 2. ASA 8.3–9.x additions
- **Global ACL** `access-group <acl> global`: applies inbound on **every** interface. It is evaluated
  **after** the interface ACL (if any). The implicit deny comes after the global ACL. Once a global ACL exists,
  the security-level implicit permit is gone for **every** interface (golden flow `A98-13`).
  An interface ACL has **no** implicit deny of its own while a global ACL exists: a flow that matches no ACE in
  the interface ACL falls through to the global ACL. An explicit `deny` ACE in the interface ACL is final.
  Order: interface ACL → global ACL → implicit deny (Cisco ASA 8.3+ configuration guide, "Access Rules";
  checked 2026-11-10).
- ACE address and service tokens: `object X`, `object-group X`, `host`, `any`, `any4`, `interface <nameif>`.
- A service object (`object SVC`) or a protocol-less service group can stand in the protocol position.

## 3. Cisco IOS 12.x ACLs (stateless router)
- Extended ACLs: numbered 100–199 and 2000–2699, and `ip access-list extended NAME`. Standard ACLs:
  1–99, 1300–1999 and `ip access-list standard NAME` (source address only).
- Named-ACL entries may start with a sequence number (`10 permit ...`). Accept it, and store it as
  `Rule.vendor_seq` without changing the ordinal `seq`.
- `ip access-group <acl> in|out` on an interface binds it. **An interface with no ACL in a direction permits
  everything** (`implicit-permit-no-acl`). IOS has no security levels.
- Inbound interface ACLs **do** filter traffic to the router's own addresses (`to_zone = "self"`). Router-
  originated traffic is **not** filtered by outbound ACLs.
- **Classify every ACL by what references it.** If an interface binds it, it's security policy. If
  `access-class` (vty), `snmp-server community ... <acl>`, `ntp access-group` or `ip http access-class`
  reference it, it's management-plane. If route-maps, NAT, crypto maps, `distribute-list` or QoS reference
  it, it's non-policy (record it, don't migrate it as security rules). If nothing references it, it's unused.
- `established` matches TCP segments with ACK or RST set. It's a flow flag, and the oracle must generate both
  values. PAN-OS is stateful and has no equivalent: the emitter **omits** `established` ACEs and creates
  a ledger entry of class `stateful-established` (unsolicited ACK/RST packets are dropped on PAN-OS, which
  is a tightening). Golden flow `IOS-01` pins this down.
- Stateless "return-traffic" ACEs (e.g. `permit udp any eq 53 any`) migrate as normal rules (same decision).
  Autopsy flags them as `return-traffic` so they become candidates for later tightening.
- Wildcard masks must be contiguous in v1. A non-contiguous wildcard is a security-relevant unparsed line.
  PAN-OS 9.0+ has wildcard address objects, but that's Phase 2.
- `log`, `log-input` are attributes only. `fragments`, `precedence`, `tos`, `dscp`, `option`, `ttl`,
  `reflect` / `evaluate` (reflexive), `dynamic` (lock-and-key), ICMP **code** keywords (e.g.
  `port-unreachable`, `host-unreachable`), CBAC `ip inspect` and zone-based firewall (`zone-pair`) are
  all security-relevant unparsed in v1.

## 4. Name tables (Cisco literal names, keyed by protocol)
Ports differ by protocol: `514/tcp` = `cmd`/`rsh` but `514/udp` = `syslog`, `512/tcp` = `exec` but
`512/udp` = `biff`. Cisco `radius` = **1645** and `radius-acct` = **1646** (not 1812/1813).

| TCP names | | UDP names | |
|---|---|---|---|
| ftp-data 20, ftp 21, ssh 22, telnet 23, smtp 25 | | echo 7, discard 9, time 37, nameserver 42 | |
| domain 53, finger 79, www/http 80, pop2 109, pop3 110 | | domain 53, bootps 67, bootpc 68, tftp 69 | |
| sunrpc 111, ident 113, nntp 119, netbios-ssn 139, imap4 143 | | sunrpc 111, ntp 123, netbios-ns 137, netbios-dgm 138 | |
| bgp 179, ldap 389, https 443, exec 512, login 513, cmd/rsh 514 | | snmp 161, snmptrap 162, xdmcp 177, isakmp 500 | |
| lpd 515, talk 517, uucp 540, klogin 543, kshell 544, rtsp 554 | | biff 512, who 513, syslog 514, talk 517, rip 520 | |
| ldaps 636, lotusnotes 1352, citrix-ica 1494, sqlnet 1521 | | radius 1645, radius-acct 1646, nfs 2049, sip 5060 | |
| h323 1720, pptp 1723, nfs 2049, ctiqbe 2748, cifs 3020 | | tacacs 49, mobile-ip 434, secureid-udp 5510 | |
| aol 5190, sip 5060, pcanywhere-data 5631, tacacs 49, kerberos 88 | | kerberos 88, pcanywhere-status 5632 | |

ICMP types: echo-reply 0, unreachable 3, source-quench 4, redirect 5, alternate-address 6, echo 8,
router-advertisement 9, router-solicitation 10, time-exceeded 11, parameter-problem 12,
timestamp-request 13, timestamp-reply 14, information-request 15, information-reply 16,
mask-request 17, mask-reply 18, traceroute 30, conversion-error 31, mobile-redirect 32.

IP protocols: icmp 1, igmp 2, ipinip 4, tcp 6, igrp 9, udp 17, gre/pptp 47, esp/ipsec 50, ah 51,
icmp6 58, eigrp 88, ospf 89, nos 94, pim 103, pcp 108, snp 109.

An unknown name is a security-relevant unparsed line. **Never guess.**

## 5. Destination zone derivation
- Build a route table from connected interface networks (`ip address`) and static routes (`route` / `ip route`).
- `to_zone` = the interface of the **longest-prefix match** on the (post-NAT, real) destination. A destination
  equal to one of the device's own interface IPs gives `self`.
- If a rule's destination set spans several egress interfaces, the emitter **splits** it into one PAN-OS
  rule per to-zone, keeping order (suffix `-z<n>`).
- Dynamic routing (OSPF/EIGRP/BGP) can't be resolved offline. Traffic that only a dynamic route would reach
  falls back to `to_zone = any` with a ledger entry of class `zone-any`. The operator can supply a
  `show route` capture to resolve it (Phase 2).

## 6. PAN-OS target
- Security policy is first-match, top-down, with zone-based `from`/`to`. The default intrazone rule is allow;
  the default interzone rule is deny. **Emit an explicit final deny** (logging on) so behaviour doesn't
  depend on the defaults, and so ASA's "no hairpin by default" stays true for intrazone traffic.
- **Like-for-like first.** The migration change uses **port-based** rules: `application any` plus explicit
  service objects. **Never** `service application-default` in the migration change, because that changes
  which ports are allowed. App-ID conversion is a separate, later change (Policy Optimizer).
- Service objects are TCP/UDP with destination port lists/ranges (`80,443,8080-8090`) and an optional source
  port. `neq` becomes a two-range list.
- ICMP restricted to specific types → a custom application per type set (ICMP type signature), so the
  match is exact. The `ping` / `icmp` App-IDs are **broader** than a single type. Using them is a widening,
  which is allowed only through an accepted tightening/ledger entry, never by default (golden flows
  `PIX-12`, `IOS-06`).
- Other IP protocols (gre 47, esp 50, ah 51, ospf 89, eigrp 88, ...) → a custom application on the IP
  protocol number, or a predefined App-ID when it's exactly equivalent. Record it in the ledger as
  class `app-id-protocol`.
- Names: ≤ 63 characters, start with an alphanumeric, characters `[A-Za-z0-9_.-]` (the emitter doesn't use
  spaces), unique per namespace, deterministic. Collisions get `-<4-hex sha1>`.
- ACL `deny` → `deny` (the action is configurable: `drop` / `reset-both`). The oracle compares permit vs not-permit.
- `inactive` → `disabled yes`. `remark` → `description`. Every rule gets the tags `src-acl:<name>` and
  `necro:<finding-id>` where applicable. Allow rules get `log-end yes`.
- Output is a **candidate** config (`set` commands, for `configure` mode or `load config partial`).
  NECROMANCER never connects to, pushes to or commits on any device.

## 7. Equivalence definition (Proof of Life)
For every generated flow `f` in a context `c`, in the source config's address space:

```
orig  = decide(original, c, f)                       # action, rule_id, to_zone
f'    = to_panos_space(f, c)                         # apply §1.5 destination mapping
res   = decide(panos_reader(emitted), zone(c), f')
```

`orig.action == res.action` and `orig.to_zone == res.to_zone` **unless** `(c, f)` is covered by an exorcism
ledger entry, in which case `res.action` must equal the entry's declared action.
Ledger classes: `tightening`, `stateful-established`, `time-range`, `to-the-box`, `zone-any`,
`app-id-protocol`, `outbound-acl`, `waived-unparsed`.
Flows with `to_zone = "self"` are compared against the emitted management profile, not the security rulebase.
