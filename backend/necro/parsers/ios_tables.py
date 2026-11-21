"""Keyword tables for the IOS parser: what each command means for policy."""

from __future__ import annotations


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


# Top-level commands that never change what is permitted.
NOT_POLICY = _words(
    """
    hostname enable service boot logging clock aaa username tacacs-server radius-server end exit
    memory-size vtp spanning-tree errdisable archive scheduler cdp lldp login privilege parser file
    mls power redundancy vlan mac-address-table ethernet license call-home key kron alias
    ntp-server transceiver ip-sla track time-range
    """
)

# ``ip <sub>`` commands that never change what is permitted.
IP_SAFE = _words(
    """
    cef domain-name domain domain-lookup name-server ssh subnet-zero classless routing dhcp finger
    icmp tftp source-route bootp forward-protocol flow-export flow multicast-routing host local
    sla telnet rcmd radius tacacs igmp pim mroute msdp default-gateway gratuitous-arps arp
    device dns hostname
    """
)

# ``ip <sub>`` commands that can change what is permitted and are not modelled in v1.
IP_RELEVANT = {
    "verify": "unicast-rpf",
    "inspect": "cbac-inspect",
    "policy": "policy-based-routing",
    "virtual-reassembly": "virtual-reassembly",
    "vrf": "vrf",
    "wccp": "wccp",
    "auth-proxy": "auth-proxy",
    "admission": "network-admission",
    "urlfilter": "url-filtering",
    "port-map": "cbac-inspect",
}

# Interface sub-commands that never change what is permitted.
IFACE_SAFE = _words(
    """
    shutdown no duplex speed mtu bandwidth encapsulation switchport channel-group spanning-tree
    load-interval keepalive cdp lldp negotiation media-type delay logging snmp standby vrrp glbp
    flowcontrol hold-queue tx-ring-limit mac-address clock description
    """
)

# ``ip <sub>`` under an interface that never change what is permitted.
IFACE_IP_SAFE = _words(
    """
    helper-address proxy-arp redirects unreachables directed-broadcast mtu flow route-cache ospf
    pim igmp tcp accounting mroute-cache nat rip split-horizon summary-address
    """
)

# Top-level commands that must never be skipped silently.
RELEVANT_UNSUPPORTED = {
    "zone": "zone-based-firewall",
    "zone-pair": "zone-based-firewall",
    "ipv6": "ipv6",
}
