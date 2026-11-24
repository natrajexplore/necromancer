/** Browser downloads and print, from text the engine already redacted. */

export function download(filename: string, text: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/** Opens the print-ready report so the person can print or "save as PDF" with the browser. */
export function printHtml(html: string): boolean {
  const url = URL.createObjectURL(new Blob([html], { type: "text/html;charset=utf-8" }));
  const win = window.open(url, "_blank", "noopener");
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  return win !== null;
}

/** File-name safe stem for a crypt name. */
export function stem(name: string): string {
  const clean = name.replace(/\.[A-Za-z0-9]+$/, "").replace(/[^A-Za-z0-9._-]+/g, "-");
  return clean.replace(/^-+|-+$/g, "") || "necromancer";
}
