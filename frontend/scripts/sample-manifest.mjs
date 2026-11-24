// Regenerates src/samples/manifest.json from the bundled sample configs: `npm run samples`.
//
// The facts on each tombstone (dialect, OS version, rule count) come from the engine itself
// (`uv run python -m necro exhume`), so the UI never re-implements parsing. The SHA-256 of each
// file lets a test notice when a sample changes and the manifest was not regenerated.
// The "died" year is fictional, like the devices: it is part of the graveyard theme.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const samples = join(root, "samples", "dead-configs");
const backend = join(root, "backend");
const out = join(here, "..", "src", "samples", "manifest.json");

const DIED = { "pix-2006-hq": 2013, "asa-8.2-branch": 2016, "ios-12-edge": 2016, "asa-9.8-dc": 2024 };

const entries = readdirSync(samples)
  .filter((name) => name.endsWith(".cfg"))
  .sort()
  .map((file) => {
    const id = file.replace(/\.cfg$/, "");
    if (!(id in DIED)) throw new Error(`no "died" year for ${file}: add it to DIED`);
    const text = readFileSync(join(samples, file), "utf8");
    const exhumed = JSON.parse(
      execFileSync("uv", ["run", "python", "-m", "necro", "exhume", join(samples, file), "--format", "json"], {
        cwd: backend,
        encoding: "utf8",
        env: { ...process.env, UV_PYTHON_PREFERENCE: process.env.UV_PYTHON_PREFERENCE ?? "only-system" },
      }),
    );
    return {
      id,
      file,
      dialect: exhumed.dialect,
      os_version: exhumed.os_version,
      rules: exhumed.acls.reduce((sum, acl) => sum + acl.rules, 0),
      died: DIED[id],
      sha256: createHash("sha256").update(text, "utf8").digest("hex"),
    };
  });

writeFileSync(out, `${JSON.stringify(entries, null, 2)}\n`);
console.log(`wrote ${entries.length} samples to ${out}`);
