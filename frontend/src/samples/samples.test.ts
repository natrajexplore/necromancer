import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { RAW_SAMPLES, SAMPLE_ENTRIES, SAMPLES } from "./index";

const DEAD_CONFIGS = join(process.env.NECRO_REPO_ROOT ?? "..", "samples", "dead-configs");

describe("bundled samples", () => {
  it("bundle every dead config in samples/, one tombstone each", () => {
    const files = readdirSync(DEAD_CONFIGS).filter((name) => name.endsWith(".cfg")).sort();
    expect(SAMPLE_ENTRIES.map((entry) => entry.file).sort()).toEqual(files);
    expect(Object.keys(RAW_SAMPLES).sort()).toEqual(files);
    expect(new Set(SAMPLES.map((crypt) => crypt.id)).size).toBe(files.length);
  });

  it.each(SAMPLE_ENTRIES)("has a manifest that matches $file (else run `npm run samples`)", (entry) => {
    const text = RAW_SAMPLES[entry.file] ?? "";
    expect(createHash("sha256").update(text, "utf8").digest("hex")).toBe(entry.sha256);
    expect(entry.rules).toBeGreaterThan(0);
    expect(["pix", "asa", "ios"]).toContain(entry.dialect);
  });

  it("ships synthetic configs only", () => {
    for (const crypt of SAMPLES) {
      expect(crypt.config.split("\n")[0]).toContain("SYNTHETIC SAMPLE");
    }
  });

  it("orders tombstones by year of death, then by name", () => {
    const years = SAMPLES.map((crypt) => crypt.sample.died);
    expect([...years].sort((a, b) => a - b)).toEqual(years);
  });
});
