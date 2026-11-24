import { useEffect, useId, useState } from "react";

import { useResurrect, type Crypt } from "../api/hooks";
import { ErrorNotice } from "../components/ErrorNotice";
import { LiveLedger, type Decision, type Decisions } from "../components/LiveLedger";
import { TighteningPanel } from "../components/TighteningPanel";
import { motionSeconds, usePrefersReducedMotion } from "../lib/motion";
import { plural } from "../lib/format";

/** The rise takes about 2.4 s (requirement 3.1); none at all under reduced motion. */
export const RISE_SECONDS = 2.4;

function Pane({ title, text, note }: { title: string; text: string; note?: string }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="min-w-0 rounded-md border border-stone bg-crypt">
      <h3 id={id} className="border-b border-stone px-3 py-2 text-sm text-ash">
        {title}
      </h3>
      {note ? (
        <p className="px-3 py-3 text-bone">{note}</p>
      ) : (
        <pre
          tabIndex={0}
          aria-labelledby={id}
          className="max-h-[32rem] overflow-auto px-3 py-3 font-mono text-sm leading-relaxed whitespace-pre text-bone"
        >
          {text}
        </pre>
      )}
    </section>
  );
}

/**
 * The original beside the candidate. Only bundled synthetic samples show their original text:
 * the engine has no endpoint that returns the redacted source, and the UI never shows a
 * config it has not seen redacted.
 */
export function SplitConfig({ crypt, candidate }: { crypt: Crypt; candidate: string }) {
  const isSample = crypt.id.startsWith("sample:");
  return (
    <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Pane
        title={`Original: ${crypt.name}`}
        text={crypt.config}
        {...(isSample
          ? {}
          : {
              note: "The original text of an uploaded config is not shown again here, because it can hold secrets and the engine does not return a redacted copy. The report holds the redacted source.",
            })}
      />
      <Pane title="PAN-OS candidate (set commands, for people to review)" text={candidate} />
    </div>
  );
}

function RiseStage({ name, seconds }: { name: string; seconds: number }) {
  return (
    <div role="status" className="flex flex-col items-center py-10" data-testid="rise">
      <div className={seconds > 0 ? "rise" : ""} aria-hidden="true">
        <svg viewBox="0 0 80 100" width="96" height="120" role="presentation">
          <path d="M10 98V40a30 30 0 0 1 60 0v58z" fill="#2a2733" stroke="#7cf5b0" strokeWidth="2" />
          <path d="M40 30v30M28 44h24" stroke="#7cf5b0" strokeWidth="3" />
        </svg>
      </div>
      <p className="mt-4 text-bone">Raising {name}…</p>
    </div>
  );
}

export function Resurrection({ crypt }: { crypt: Crypt }) {
  const reduced = usePrefersReducedMotion();
  const [started, setStarted] = useState(false);
  const [risen, setRisen] = useState(false);
  const [decisions, setDecisions] = useState<Decisions>({});
  const result = useResurrect(crypt);
  const seconds = motionSeconds(RISE_SECONDS, reduced);

  useEffect(() => {
    if (!started) return undefined;
    if (seconds === 0) {
      setRisen(true);
      return undefined;
    }
    const timer = window.setTimeout(() => setRisen(true), seconds * 1000);
    return () => window.clearTimeout(timer);
  }, [started, seconds]);

  const decide = (id: string, decision: Decision | null) =>
    setDecisions((current) => {
      const next = { ...current };
      if (decision) next[id] = decision;
      else delete next[id];
      return next;
    });

  if (!started) {
    return (
      <div>
        <p className="max-w-3xl text-ash">
          Resurrect translates the config to a vendor-neutral model and emits PAN-OS set commands
          that behave like the original. Nothing is connected or pushed anywhere.
        </p>
        <button
          type="button"
          onClick={() => setStarted(true)}
          className="mt-4 rounded-md bg-spectral px-5 py-2.5 font-semibold text-void"
        >
          Resurrect
        </button>
      </div>
    );
  }
  if (result.isError) return <ErrorNotice error={result.error} what="resurrected" />;
  if (!risen || !result.data) return <RiseStage name={crypt.name} seconds={seconds} />;

  const data = result.data;
  return (
    <div aria-live="polite">
      <p className="text-bone">
        {plural(data.config_lines, "line")} of PAN-OS candidate config,{" "}
        {plural(data.ledger.length, "ledger entry", "ledger entries")},{" "}
        {data.blocking.length === 0
          ? "no blocking lines"
          : `${plural(data.blocking.length, "line")} that block the verdict`}
        .
      </p>
      {data.blocking.length > 0 && (
        <ul className="mt-2 rounded-md border border-blood/60 bg-crypt px-4 py-3 text-bone">
          {data.blocking.map((line) => (
            <li key={line.line_no}>
              Line {line.line_no} ({line.reason}): <code className="font-mono">{line.text}</code>
            </li>
          ))}
        </ul>
      )}
      {data.unsupported.length > 0 && (
        <p className="mt-2 text-candle">Not emitted: {data.unsupported.join("; ")}</p>
      )}
      {data.notes.map((note) => (
        <p key={note} className="mt-2 text-ash">
          {note}
        </p>
      ))}
      <SplitConfig crypt={crypt} candidate={data.config} />
      <TighteningPanel entries={data.ledger} decisions={decisions} onDecide={decide} />
      <LiveLedger entries={data.ledger} decisions={decisions} />
    </div>
  );
}
