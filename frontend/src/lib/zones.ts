import type { InterfaceSummary } from "../api/types";

export interface ZoneRow {
  nameif: string;
  hw_name: string;
  security_level: number;
  address: string;
  zone: string; // PAN-OS zone name, or "" when the emitted config has none for it
}

/** PAN-OS `set zone <zone> network layer3 <ethernetN/M>`, with the interface's address. */
export function zoneMap(interfaces: InterfaceSummary[], panos: string): ZoneRow[] {
  const zoneOfIface = new Map<string, string>();
  const ipOfIface = new Map<string, string>();
  for (const line of panos.split("\n")) {
    const zone = /^set zone (\S+) network layer3 (?:\[ )?(\S+)/.exec(line);
    if (zone) zoneOfIface.set(zone[2] as string, zone[1] as string);
    const ip = /^set network interface ethernet (\S+) layer3 ip (\S+)/.exec(line);
    if (ip) ipOfIface.set((ip[2] as string).split("/")[0] as string, ip[1] as string);
  }
  return interfaces.map((i) => {
    const iface = ipOfIface.get(i.address.split("/")[0] ?? "");
    return { ...i, zone: (iface && zoneOfIface.get(iface)) || "" };
  });
}
