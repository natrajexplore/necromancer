/**
 * Design tokens from the haunted-ui steering doc. styles.css declares the same values for
 * Tailwind (`@theme`); tokens.test.ts checks that the two agree and that every text/background
 * pair the UI uses meets WCAG AA (4.5:1 for normal text).
 */
export const colors = {
  void: "#0b0a10", // page background
  crypt: "#16141d", // panels and cards
  stone: "#2a2733", // tombstones
  bone: "#e9e4d8", // body text
  ash: "#b3ad9f", // secondary text
  spectral: "#7cf5b0", // alive / passing
  blood: "#e5484d", // divergence / critical
  candle: "#f5b74a", // warnings
} as const;

export type ColorToken = keyof typeof colors;

/** Text/background pairs the UI actually renders. Add a pair here before using it. */
export const textPairs: ReadonlyArray<readonly [text: ColorToken, background: ColorToken]> = [
  ["bone", "void"],
  ["bone", "crypt"],
  ["bone", "stone"],
  ["ash", "void"],
  ["ash", "crypt"],
  ["ash", "stone"],
  ["spectral", "void"],
  ["spectral", "crypt"],
  ["spectral", "stone"],
  ["blood", "void"],
  ["blood", "crypt"],
  ["candle", "void"],
  ["candle", "crypt"],
  ["candle", "stone"],
  ["void", "spectral"], // primary button
  ["void", "candle"],
];

function channel(value: number): number {
  const c = value / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

/** WCAG 2.x relative luminance of a `#rrggbb` colour. */
export function luminance(hex: string): number {
  const match = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (!match) throw new Error(`not a #rrggbb colour: ${hex}`);
  const [r, g, b] = match.slice(1).map((part) => channel(Number.parseInt(part, 16)));
  return 0.2126 * (r ?? 0) + 0.7152 * (g ?? 0) + 0.0722 * (b ?? 0);
}

/** WCAG 2.x contrast ratio between two colours (1 to 21). */
export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}
