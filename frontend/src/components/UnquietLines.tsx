import { useId } from "react";

import type { LineIssue } from "../api/types";
import { Hint } from "./Hint";

function LineTable({ lines, caption }: { lines: LineIssue[]; caption: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="text-ash">
          <tr>
            <th scope="col" className="py-2 pr-4 font-medium">
              Line
            </th>
            <th scope="col" className="py-2 pr-4 font-medium">
              Text (redacted)
            </th>
            <th scope="col" className="py-2 pr-4 font-medium">
              Reason
            </th>
            <th scope="col" className="py-2 font-medium">
              Status
            </th>
          </tr>
        </thead>
        <tbody>
          {lines.map((line) => (
            <tr key={line.line_no} className="border-t border-stone align-top">
              <td className="py-2 pr-4 font-mono tabular-nums">{line.line_no}</td>
              <td className="py-2 pr-4 font-mono break-all whitespace-pre-wrap">{line.text}</td>
              <td className="py-2 pr-4 font-mono">{line.reason}</td>
              <td className="py-2">
                {line.waived ? (
                  <span className="text-spectral">waived</span>
                ) : line.security_relevant ? (
                  <span className="text-candle">blocks the verdict</span>
                ) : (
                  <span className="text-ash">recorded</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Lines the engine could not migrate (requirement 1.4). Security-relevant ones are listed in
 * full, never hidden behind the theme; the rest are one click away.
 */
export function UnquietLines({ lines }: { lines: LineIssue[] }) {
  const headingId = useId();
  const relevant = lines.filter((line) => line.security_relevant);
  const other = lines.filter((line) => !line.security_relevant);
  return (
    <section aria-labelledby={headingId} className="mt-6">
      <h3 id={headingId} className="font-display text-xl text-bone">
        <Hint explain="Security-relevant lines the engine could not migrate or that are out of scope. Each one blocks the readiness verdict until a named person waives it.">
          Unquiet lines
        </Hint>{" "}
        <span className="font-sans text-base text-ash">({relevant.length})</span>
      </h3>
      {relevant.length === 0 ? (
        <p className="mt-2 text-ash">None. Every security-relevant line was accounted for.</p>
      ) : (
        <LineTable lines={relevant} caption="Security-relevant lines that were not migrated" />
      )}
      {other.length > 0 && (
        <details className="mt-4">
          <summary className="cursor-pointer text-ash">
            Other lines not migrated ({other.length}, not security-relevant)
          </summary>
          <LineTable lines={other} caption="Lines that were not migrated and are not security-relevant" />
        </details>
      )}
    </section>
  );
}
