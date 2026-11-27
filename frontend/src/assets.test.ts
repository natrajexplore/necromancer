import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";

import { describe, expect, it } from "vitest";

/**
 * Graveyard-ui requirement 6.3: no vendor logos or trademarked imagery. The UI draws its own
 * headstone as inline SVG, loads no raster images and no remote assets, and names vendors in text.
 */
const root = join(import.meta.dirname, "..");
const SCANNED = ["src", "public", "index.html"];
const RASTER = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico", ".tiff"]);

function files(path: string): string[] {
  if (statSync(path).isFile()) return [path];
  return readdirSync(path).flatMap((name) => files(join(path, name)));
}

const all = SCANNED.flatMap((entry) => files(join(root, entry)));

describe("assets", () => {
  it("ships no raster images or logos", () => {
    expect(all.filter((file) => RASTER.has(extname(file).toLowerCase()))).toEqual([]);
  });

  it("allows one hand-drawn SVG file: the favicon", () => {
    const svgs = all.filter((file) => extname(file) === ".svg").map((file) => file.slice(root.length + 1).replaceAll("\\", "/"));
    expect(svgs).toEqual(["public/favicon.svg"]);
  });

  it("has no <img> elements and loads nothing from a remote host", () => {
    for (const file of all.filter((f) => /\.(tsx?|css|html|svg)$/.test(f) && !f.endsWith(".test.ts") && !f.endsWith(".test.tsx"))) {
      const text = readFileSync(file, "utf8");
      expect(text, file).not.toMatch(/<img[\s>]/i);
      // the SVG namespace is an identifier, not a request
      expect(text.replaceAll("http://www.w3.org/2000/svg", ""), file).not.toMatch(/url\(\s*["']?https?:|src=["']https?:|href=["']https?:/i);
    }
  });
});
