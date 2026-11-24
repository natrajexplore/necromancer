/**
 * The runbook is section "Runbook" of the Grimoire's Markdown: `###` subsections holding
 * paragraphs, bullet lists and pipe tables. The API has no separate runbook field, so the UI
 * reads it from the report text (which is already redacted).
 */
export interface RunbookTable {
  headers: string[];
  rows: string[][];
}

export interface RunbookPart {
  title: string;
  text: string[]; // paragraphs and bullet lines, in order
  tables: RunbookTable[];
}

function splitRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  const cells: string[] = [];
  let cell = "";
  for (let i = 0; i < trimmed.length; i += 1) {
    const ch = trimmed[i] as string;
    if (ch === "\\" && trimmed[i + 1] === "|") {
      cell += "|";
      i += 1;
    } else if (ch === "|") {
      cells.push(cell.trim());
      cell = "";
    } else {
      cell += ch;
    }
  }
  cells.push(cell.trim());
  return cells;
}

const isTableLine = (line: string) => line.trimStart().startsWith("|");
const isSeparator = (line: string) => /^\|?[\s:|-]+\|?$/.test(line.trim()) && line.includes("-");

/** The lines of the section whose `## n. Title` heading has this title. */
function sectionLines(markdown: string, title: string): string[] {
  const lines = markdown.split(/\r?\n/);
  const heading = (line: string) => /^##\s+(?:\d+\.\s+)?(.*)$/.exec(line);
  const start = lines.findIndex((line) => heading(line)?.[1]?.trim() === title);
  if (start < 0) return [];
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((line) => /^##\s/.test(line));
  return end < 0 ? rest : rest.slice(0, end);
}

export function parseRunbook(markdown: string): RunbookPart[] {
  const parts: RunbookPart[] = [];
  let current: RunbookPart | null = null;
  let table: string[] | null = null;
  const flush = () => {
    if (current && table && table.length > 0) {
      const [head, ...body] = table.filter((line) => !isSeparator(line));
      if (head) current.tables.push({ headers: splitRow(head), rows: body.map(splitRow) });
    }
    table = null;
  };
  for (const line of sectionLines(markdown, "Runbook")) {
    const sub = /^###\s+(.*)$/.exec(line);
    if (sub) {
      flush();
      current = { title: (sub[1] ?? "").trim(), text: [], tables: [] };
      parts.push(current);
    } else if (!current) {
      continue;
    } else if (isTableLine(line)) {
      table = [...(table ?? []), line];
    } else {
      flush();
      if (line.trim() !== "") current.text.push(line.trim().replace(/^[-*]\s+/, ""));
    }
  }
  flush();
  return parts;
}

/** Plain text of a part, for its "copy all" button. */
export function partToText(part: RunbookPart): string {
  const lines = [part.title, ...part.text];
  for (const table of part.tables) {
    for (const row of table.rows) lines.push(row.join("  "));
  }
  return lines.join("\n");
}

/** The cells to copy for one table row: the Command column when there is one, else the step. */
export function copyTarget(table: RunbookTable, row: string[]): string {
  const at = table.headers.findIndex((h) => h === "Command" || h === "Step");
  return at >= 0 ? (row[at] ?? "") : row.join("  ");
}
