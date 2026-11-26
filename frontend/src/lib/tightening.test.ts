import { describe, expect, it } from "vitest";

import type { Proposal } from "../api/types";
import { buildSelection, parseNetworks } from "./tightening";

const NOW = new Date("2026-11-24T12:00:00Z");

function proposal(overrides: Partial<Proposal>): Proposal {
  return {
    finding_id: "AUT-0001",
    finding_type: "shadowed",
    severity: "medium",
    kind: "remove-rule",
    rule_ref: "IN#3",
    summary: "Remove IN#3.",
    needs_networks: false,
    ...overrides,
  };
}

const REMOVE = proposal({});
const NARROW = proposal({
  finding_id: "AUT-0002",
  kind: "narrow-any",
  rule_ref: "IN#2",
  needs_networks: true,
});

describe("parseNetworks", () => {
  it("splits on commas, semicolons and whitespace, and drops empties", () => {
    expect(parseNetworks(" 10.0.0.0/8,192.0.2.0/24 ; 198.51.100.0/24\n")).toEqual([
      "10.0.0.0/8",
      "192.0.2.0/24",
      "198.51.100.0/24",
    ]);
    expect(parseNetworks("  ,, ")).toEqual([]);
  });
});

describe("buildSelection", () => {
  it("refuses until a proposal is accepted", () => {
    expect(buildSelection([REMOVE], {}, {}, "A. Reviewer", NOW)).toEqual({
      ok: false,
      reason: "Accept at least one proposal to tighten.",
    });
    const onlyRejected = buildSelection([REMOVE], { "AUT-0001": "rejected" }, {}, "A. Reviewer", NOW);
    expect(onlyRejected.ok).toBe(false);
  });

  it("refuses without a named approver", () => {
    const built = buildSelection([REMOVE], { "AUT-0001": "accepted" }, {}, "   ", NOW);
    expect(built).toMatchObject({ ok: false });
    expect(built.ok === false && built.reason).toMatch(/Name the approver/);
  });

  it("refuses an accepted narrowing that has no confirmed network", () => {
    const built = buildSelection([NARROW], { "AUT-0002": "accepted" }, { "AUT-0002": " , " }, "A. Reviewer", NOW);
    expect(built.ok === false && built.reason).toMatch(/Confirm the networks for IN#2/);
  });

  it("sends a choice and a dated, named decision for each decided proposal", () => {
    const built = buildSelection(
      [REMOVE, NARROW, proposal({ finding_id: "AUT-0003", rule_ref: "IN#9" })],
      { "AUT-0001": "accepted", "AUT-0002": "accepted" },
      { "AUT-0002": "10.0.0.0/8, 192.0.2.0/24" },
      " A. Reviewer ",
      NOW,
    );
    expect(built).toEqual({
      ok: true,
      selection: {
        choices: [
          { finding_id: "AUT-0001", kind: "remove-rule" },
          { finding_id: "AUT-0002", kind: "narrow-any", networks: ["10.0.0.0/8", "192.0.2.0/24"] },
        ],
        approvals: {
          "AUT-0001": { approval: "accepted", approver: "A. Reviewer", decided_at: "2026-11-24T12:00:00.000Z" },
          "AUT-0002": { approval: "accepted", approver: "A. Reviewer", decided_at: "2026-11-24T12:00:00.000Z" },
        },
      },
    });
  });

  it("sends a rejected proposal as a rejected decision, so the ledger records it", () => {
    const built = buildSelection(
      [REMOVE, NARROW],
      { "AUT-0001": "accepted", "AUT-0002": "rejected" },
      {},
      "A. Reviewer",
      NOW,
    );
    expect(built.ok && built.selection.approvals["AUT-0002"]?.approval).toBe("rejected");
    expect(built.ok && built.selection.choices[1]).toEqual({ finding_id: "AUT-0002", kind: "narrow-any", networks: [] });
  });
});
