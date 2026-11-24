import { useState } from "react";

import { copyTarget, partToText, type RunbookPart } from "../lib/runbook";

export function CopyButton({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
    window.setTimeout(() => setState("idle"), 2000);
  };
  return (
    <button
      type="button"
      onClick={() => void copy()}
      aria-label={label}
      className="shrink-0 rounded border border-stone px-2 py-1 text-sm text-bone hover:border-spectral"
    >
      {state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : "Copy"}
    </button>
  );
}

/** The runbook as plain, printable text with a copy button for every command and step. */
export function RunbookView({ parts }: { parts: RunbookPart[] }) {
  if (parts.length === 0) return <p>The report has no runbook section.</p>;
  return (
    <div className="space-y-6">
      {parts.map((part) => (
        <section key={part.title} aria-label={part.title}>
          <div className="flex items-center justify-between gap-3">
            <h4 className="text-lg font-semibold">{part.title}</h4>
            <CopyButton text={partToText(part)} label={`Copy all of ${part.title}`} />
          </div>
          {part.text.map((line) => (
            <p key={line} className="mt-1">
              {line}
            </p>
          ))}
          {part.tables.map((table, index) => (
            <table key={index} className="mt-2 w-full text-left text-sm">
              <thead>
                <tr>
                  {table.headers.map((header) => (
                    <th key={header} scope="col" className="py-1 pr-3 font-semibold">
                      {header}
                    </th>
                  ))}
                  <th scope="col" className="py-1 font-semibold">
                    <span className="sr-only">Copy</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {table.rows.map((row, r) => (
                  <tr key={r} className="border-t border-stone align-top">
                    {row.map((cell, c) => (
                      <td key={c} className="py-1 pr-3">
                        {table.headers[c] === "Command" ? (
                          <code className="font-mono">{cell}</code>
                        ) : (
                          cell
                        )}
                      </td>
                    ))}
                    <td className="py-1">
                      <CopyButton
                        text={copyTarget(table, row)}
                        label={`Copy ${row[0] || "row"} of ${part.title}`}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ))}
        </section>
      ))}
    </div>
  );
}
