import { useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState, type DragEvent } from "react";

import { MAX_CONFIG_BYTES } from "../api/client";
import { exhumeQuery, type Crypt } from "../api/hooks";
import { ErrorNotice } from "./ErrorNotice";

/**
 * The "Exhume your own" tombstone: drop a file, pick one, or paste text. The config goes to
 * /v1/exhume and, once it parses, gets its own tombstone. Nothing is stored anywhere.
 */
export function ExhumeZone({ onExhumed }: { onExhumed: (crypt: Crypt) => void }) {
  const queryClient = useQueryClient();
  const counter = useRef(0);
  const [pasted, setPasted] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const headingId = useId();
  const fileId = useId();
  const pasteId = useId();

  async function exhume(name: string, config: string) {
    counter.current += 1;
    const crypt: Crypt = { id: `upload:${counter.current}`, name, config };
    setBusy(true);
    setError(null);
    try {
      await queryClient.fetchQuery(exhumeQuery(crypt));
      onExhumed(crypt);
      setPasted("");
    } catch (failure) {
      queryClient.removeQueries({ queryKey: exhumeQuery(crypt).queryKey });
      setError(failure);
    } finally {
      setBusy(false);
    }
  }

  async function exhumeFile(file: File | undefined) {
    if (!file) return;
    if (file.size > MAX_CONFIG_BYTES) {
      setError(new Error(`${file.name} is larger than the 2 MB limit.`));
      return;
    }
    await exhume(file.name, await file.text());
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    void exhumeFile(event.dataTransfer.files[0]);
  }

  return (
    <section
      aria-labelledby={headingId}
      className="flex h-full min-h-64 flex-col gap-3 rounded-t-[5rem] rounded-b-md border border-dashed border-ash/50 bg-crypt px-5 pt-10 pb-5"
    >
      <h3 id={headingId} className="text-center font-display text-xl text-bone">
        Exhume your own
      </h3>
      <div
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        data-testid="drop-zone"
        className={`rounded-md border border-dashed px-3 py-4 text-center text-sm ${
          dragging ? "border-spectral text-spectral" : "border-stone text-ash"
        } has-[input:focus-visible]:border-spectral has-[input:focus-visible]:outline-2 has-[input:focus-visible]:outline-offset-2 has-[input:focus-visible]:outline-spectral`}
      >
        Drop a config file here, or{" "}
        <label htmlFor={fileId} className="cursor-pointer text-spectral underline underline-offset-4">
          choose a file
        </label>
        <input
          id={fileId}
          type="file"
          accept=".cfg,.conf,.txt,text/plain"
          className="sr-only"
          disabled={busy}
          onChange={(event) => {
            void exhumeFile(event.target.files?.[0]);
            event.target.value = "";
          }}
        />
      </div>
      <label htmlFor={pasteId} className="text-sm text-ash">
        Or paste a config
      </label>
      <textarea
        id={pasteId}
        value={pasted}
        onChange={(event) => setPasted(event.target.value)}
        rows={4}
        spellCheck={false}
        className="w-full resize-y rounded-md border border-stone bg-void p-2 font-mono text-xs text-bone"
      />
      <button
        type="button"
        disabled={busy || pasted.trim() === ""}
        onClick={() => void exhume(`Pasted config ${counter.current + 1}`, pasted)}
        className="rounded-md bg-spectral px-4 py-2 font-semibold text-void disabled:cursor-not-allowed disabled:opacity-50"
      >
        {busy ? "Exhuming…" : "Exhume"}
      </button>
      {error !== null && <ErrorNotice error={error} />}
    </section>
  );
}
