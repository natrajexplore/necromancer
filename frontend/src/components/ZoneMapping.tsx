import type { Finding, InterfaceSummary } from "../api/types";
import { zoneMap } from "../lib/zones";

/**
 * Interface, security level and PAN-OS zone. An interface with no ACL bound inbound is marked
 * "unfiltered": the autopsy reports it as an `unfiltered-interface` finding for that zone.
 */
export function ZoneMapping({
  interfaces,
  panos,
  findings,
  loading,
}: {
  interfaces: InterfaceSummary[];
  panos: string;
  findings: Finding[];
  loading: boolean;
}) {
  const rows = zoneMap(interfaces, panos);
  const unfiltered = new Set(
    findings.filter((f) => f.type === "unfiltered-interface").map((f) => f.zone),
  );
  return (
    <section className="mt-8" aria-labelledby="zone-mapping-title">
      <h3 id="zone-mapping-title" className="font-display text-xl text-bone">
        Zone mapping
      </h3>
      {rows.length === 0 ? (
        <p className="mt-2 text-ash">The config names no interfaces.</p>
      ) : (
        <table className="mt-2 w-full max-w-3xl text-left">
          <caption className="sr-only">Interfaces and the PAN-OS zones they map to</caption>
          <thead className="text-sm text-ash">
            <tr>
              <th scope="col" className="py-2 pr-4 font-normal">Interface</th>
              <th scope="col" className="py-2 pr-4 font-normal">Security level</th>
              <th scope="col" className="py-2 pr-4 font-normal">PAN-OS zone</th>
              <th scope="col" className="py-2 font-normal">Inbound filtering</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.nameif} className="border-t border-stone">
                <th scope="row" className="py-2 pr-4 font-normal text-bone">
                  {row.nameif} <span className="text-ash">({row.hw_name})</span>
                </th>
                <td className="py-2 pr-4 text-bone">{row.security_level}</td>
                <td className="py-2 pr-4 font-mono text-bone">
                  {row.zone || (loading ? "…" : "not emitted")}
                </td>
                <td className="py-2">
                  {unfiltered.has(row.nameif) || unfiltered.has(row.zone) ? (
                    <span className="text-candle">Unfiltered: no ACL bound inbound</span>
                  ) : (
                    <span className="text-bone">ACL bound</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
