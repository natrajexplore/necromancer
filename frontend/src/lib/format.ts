import type { DialectName } from "../api/types";

/** Vendor and platform names appear as plain text only (no logos). */
const DIALECTS: Record<DialectName, string> = {
  pix: "Cisco PIX",
  asa: "Cisco ASA",
  ios: "Cisco IOS",
};

export function dialectLabel(dialect: DialectName, osVersion = ""): string {
  return `${DIALECTS[dialect]} ${osVersion}`.trim();
}

/** A ratio as a percentage, rounded down so that 99.96% never reads as 100%. */
export function percent(ratio: number): string {
  const tenths = Math.floor(ratio * 1000) / 10;
  return Number.isInteger(tenths) ? `${tenths}%` : `${tenths.toFixed(1)}%`;
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}
