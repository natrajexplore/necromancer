"""Keyword tables for the PIX/ASA parser: what each top-level command means."""

from __future__ import annotations

NOT_POLICY = frozenset(
    {
        "hostname",
        "domain-name",
        "enable",
        "passwd",
        "password",
        "username",
        "logging",
        "ntp",
        "clock",
        "pager",
        "console",
        "terminal",
        "banner",
        "boot",
        "ftp",
        "dns",
        "dhcpd",
        "dhcprelay",
        "dhcp-client",
        "aaa-server",
        "aaa",
        "asdm",
        "arp",
        "mtu",
        "monitor-interface",
        "failover",
        "timeout",
        "service",
        "prompt",
        "call-home",
        "hw-module",
        "smtp-server",
        "cryptochecksum",
        "ssl",
        "kerberos",
        "privilege",
        "exit",
        "quit",
        "threat-detection",
        "perfmon",
        "floodguard",
        "pdm",
        "jumbo-frame",
        "mac-address-table",
        "dns-guard",
        "time-range",
    }
)
INSPECTION = frozenset({"fixup", "inspect", "class-map", "policy-map", "service-policy", "class"})
VPN = frozenset(
    {
        "crypto",
        "isakmp",
        "ipsec",
        "tunnel-group",
        "group-policy",
        "webvpn",
        "vpn-sessiondb",
        "vpngroup",
        "vpnclient",
        "tunnel-group-map",
    }
)
RELEVANT_UNSUPPORTED = {
    "conduit": "pix-legacy-conduit",
    "outbound": "pix-legacy-outbound",
    "apply": "pix-legacy-apply",
    "established": "pix-legacy-established",
    "sysopt": "sysopt-unmodelled",
    "shun": "shun-unmodelled",
    "ipv6": "ipv6",
    "user-identity": "identity-firewall",
    "object": "asa-8.3-object",
}
IFACE_CHILD_NOT_POLICY = frozenset(
    {
        "shutdown",
        "no",
        "speed",
        "duplex",
        "vlan",
        "management-only",
        "hold-time",
        "delay",
        "mac-address",
        "flowcontrol",
        "forward",
        "pppoe",
        "lacp",
        "channel-group",
        "backup",
    }
)
PIX_HW_ATTRS = frozenset({"auto", "10baset", "100basetx", "100full", "10full", "1000auto"})
