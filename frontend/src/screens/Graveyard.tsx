import { useState } from "react";

import { useExhume, type Crypt } from "../api/hooks";
import { CryptDetails } from "../components/CryptDetails";
import { ExhumeZone } from "../components/ExhumeZone";
import { Tombstone } from "../components/Tombstone";
import { confidence, dialectLabel, percent, plural } from "../lib/format";
import { SAMPLES } from "../samples";

/** Requirement 1.3: said plainly, outside the theme, on the landing screen. */
function PrivacyNote() {
  return (
    <p role="note" className="mt-4 max-w-3xl rounded-md border border-stone bg-crypt px-4 py-3 text-sm text-bone">
      Configs you exhume are processed in memory and are not stored. This is a public demo: use
      synthetic configs only, never the configuration of a real device.
    </p>
  );
}

/** A config the user brought: its tombstone shows what exhume found (cached, no new request). */
function UploadTombstone({ crypt, selected, onSelect }: { crypt: Crypt; selected: boolean; onSelect: () => void }) {
  const { data } = useExhume(crypt);
  if (!data) return null;
  const relevant = data.unparsed.filter((line) => line.security_relevant).length;
  const notMigrated = `${data.unparsed.length} not migrated`;
  return (
    <Tombstone
      title={crypt.name}
      selected={selected}
      onSelect={onSelect}
      label={`${crypt.name}: ${dialectLabel(data.dialect, data.os_version)}, detection confidence ${confidence(data.detection_confidence)}, coverage ${percent(data.coverage.ratio)}, ${plural(data.unparsed.length, "line")} not migrated, ${relevant} security-relevant`}
      lines={[
        dialectLabel(data.dialect, data.os_version),
        `confidence ${confidence(data.detection_confidence)}`,
        `coverage ${percent(data.coverage.ratio)}`,
        relevant > 0 ? (
          <>
            {notMigrated}, <span className="text-candle">{relevant} security-relevant</span>
          </>
        ) : (
          notMigrated
        ),
      ]}
    />
  );
}

export function Graveyard() {
  const [uploads, setUploads] = useState<Crypt[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = [...SAMPLES, ...uploads].find((crypt) => crypt.id === selectedId) ?? null;

  return (
    <section aria-labelledby="graveyard-title">
      <h2 id="graveyard-title" className="font-display text-3xl text-bone">
        The graveyard
      </h2>
      <p className="mt-2 max-w-3xl text-ash">
        Each tombstone is a firewall config from an end-of-life device. Open one to exhume it, or
        bring your own.
      </p>
      <PrivacyNote />

      <ul className="mt-8 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        {SAMPLES.map((crypt) => {
          const { sample } = crypt;
          const platform = dialectLabel(sample.dialect, sample.os_version);
          return (
            <li key={crypt.id}>
              <Tombstone
                title={crypt.name}
                selected={crypt.id === selectedId}
                onSelect={() => setSelectedId(crypt.id)}
                label={`${crypt.name}: synthetic ${platform} config, ${plural(sample.rules, "rule")}, died ${sample.died} (fictional year)`}
                lines={[platform, plural(sample.rules, "rule"), `died ${sample.died}`]}
              />
            </li>
          );
        })}
        {uploads.map((crypt) => (
          <li key={crypt.id}>
            <UploadTombstone crypt={crypt} selected={crypt.id === selectedId} onSelect={() => setSelectedId(crypt.id)} />
          </li>
        ))}
        <li>
          <ExhumeZone
            onExhumed={(crypt) => {
              setUploads((current) => [...current, crypt]);
              setSelectedId(crypt.id);
            }}
          />
        </li>
      </ul>
      <p className="mt-3 text-sm text-ash">
        The sample configs are synthetic, and so are their dates of death.
      </p>

      {selected && <CryptDetails key={selected.id} crypt={selected} />}
    </section>
  );
}
