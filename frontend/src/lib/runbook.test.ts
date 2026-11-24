import { describe, expect, it } from "vitest";

import { copyTarget, parseRunbook, partToText } from "./runbook";

const REPORT = `# Report

## 8. Zone-to-zone matrix

| A | B |
| --- | --- |
| not | runbook |

## 9. Runbook

### Pre-cutover checks (P6)

| Done | ID | Step |
| --- | --- | --- |
| [ ] | P6.1 | Back up the source and the target |

### Verification commands on the target (PAN-OS)

Run each command in operational mode.

| ID | Command | Expected result |
| --- | --- | --- |
| V1 | test security-policy-match from outside to inside source 198.51.100.7 \\| x | allow |

### Rollback (P9)

- Trigger one
- Trigger two

## 10. Appendix

| later | table |
`;

describe("parseRunbook", () => {
  const parts = parseRunbook(REPORT);

  it("reads only the Runbook section, as one part per ### heading", () => {
    expect(parts.map((part) => part.title)).toEqual([
      "Pre-cutover checks (P6)",
      "Verification commands on the target (PAN-OS)",
      "Rollback (P9)",
    ]);
  });

  it("reads tables, unescaping a pipe inside a cell", () => {
    const table = parts[1]?.tables[0];
    expect(table?.headers).toEqual(["ID", "Command", "Expected result"]);
    expect(table?.rows[0]?.[1]).toBe(
      "test security-policy-match from outside to inside source 198.51.100.7 | x",
    );
  });

  it("keeps paragraphs and bullets", () => {
    expect(parts[1]?.text).toEqual(["Run each command in operational mode."]);
    expect(parts[2]?.text).toEqual(["Trigger one", "Trigger two"]);
  });

  it("copies the Command or Step cell of a row, and everything for a whole part", () => {
    const table = parts[1]?.tables[0];
    const step = parts[0]?.tables[0];
    expect(table && copyTarget(table, table.rows[0] ?? [])).toContain("test security-policy-match");
    expect(step && copyTarget(step, step.rows[0] ?? [])).toBe("Back up the source and the target");
    expect(parts[2] && partToText(parts[2])).toBe("Rollback (P9)\nTrigger one\nTrigger two");
  });

  it("returns nothing when the report has no runbook", () => {
    expect(parseRunbook("# x\n\n## 1. Verdict\n")).toEqual([]);
  });
});
