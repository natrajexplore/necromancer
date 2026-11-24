import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { colors, contrast, luminance, textPairs } from "./tokens";

// Read from disk: the test config turns CSS processing off, which empties CSS imports.
const styles = readFileSync(join(process.env.NECRO_REPO_ROOT ?? "..", "frontend", "src", "styles.css"), "utf8");

describe("design tokens", () => {
  it("match the palette in the haunted-ui steering doc", () => {
    expect(colors.void).toBe("#0b0a10");
    expect(colors.bone).toBe("#e9e4d8");
    expect(colors.spectral).toBe("#7cf5b0");
    expect(colors.blood).toBe("#e5484d");
    expect(colors.candle).toBe("#f5b74a");
  });

  it("are the same values Tailwind gets from styles.css", () => {
    for (const [name, value] of Object.entries(colors)) {
      expect(styles).toContain(`--color-${name}: ${value};`);
    }
  });

  it.each(textPairs)("%s text on %s meets WCAG AA (4.5:1)", (text, background) => {
    expect(contrast(colors[text], colors[background])).toBeGreaterThanOrEqual(4.5);
  });

  it("computes WCAG contrast correctly", () => {
    expect(contrast("#000000", "#ffffff")).toBeCloseTo(21, 5);
    expect(contrast("#777777", "#777777")).toBe(1);
    expect(luminance("#ffffff")).toBeCloseTo(1, 5);
    expect(() => luminance("red")).toThrow("not a #rrggbb colour");
  });

  it("turn every animation off under prefers-reduced-motion", () => {
    const block = styles.slice(styles.indexOf("@media (prefers-reduced-motion: reduce)"));
    expect(block).toContain("animation-duration: 0s !important");
    expect(block).toContain("transition-duration: 0s !important");
  });

  it("use self-hosted OFL fonts and no remote font services", () => {
    expect(styles).toContain('"IM Fell English SC"');
    expect(styles).toContain('"Inter Variable"');
    expect(styles).toContain('"JetBrains Mono Variable"');
    expect(styles).not.toMatch(/fonts\.googleapis|https?:\/\//);
  });
});
