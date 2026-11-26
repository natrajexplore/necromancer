import type { Choice, Proposal, TighteningSelection } from "../api/types";

export type FindingDecision = "accepted" | "rejected";

/** The person's decisions on proposals, by finding id. A missing id is undecided. */
export type FindingDecisions = Record<string, FindingDecision>;

/** Confirmed networks as typed, by finding id (narrow-any only). */
export type NetworkText = Record<string, string>;

export const REMEDIATION_LABEL: Record<Proposal["kind"], string> = {
  "remove-rule": "Remove the rule",
  "replace-service": "Remove the insecure service",
  "narrow-any": "Narrow any to confirmed networks",
  advise: "Note only (no rule changes)",
};

/** Splits "10.0.0.0/8, 192.0.2.0/24" into networks. The engine validates them. */
export function parseNetworks(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((part) => part.trim())
    .filter((part) => part !== "");
}

export type Built = { ok: true; selection: TighteningSelection } | { ok: false; reason: string };

/**
 * The request body for a tightening: one choice per decided finding, and the approver's decision
 * on each. Accepted proposals are applied. Rejected ones are sent too, so their ledger entries
 * stay in the record as rejected. Refuses while no proposal is accepted, no approver is named, or
 * an accepted narrowing has no confirmed network.
 */
export function buildSelection(
  proposals: Proposal[],
  decisions: FindingDecisions,
  networks: NetworkText,
  approver: string,
  now: Date,
): Built {
  const decided = proposals.filter((p) => decisions[p.finding_id] !== undefined);
  if (!decided.some((p) => decisions[p.finding_id] === "accepted")) {
    return { ok: false, reason: "Accept at least one proposal to tighten." };
  }
  const name = approver.trim();
  if (name === "") {
    return { ok: false, reason: "Name the approver. A decision needs a named person." };
  }
  const choices: Choice[] = [];
  const approvals: TighteningSelection["approvals"] = {};
  for (const p of decided) {
    const decision = decisions[p.finding_id] as FindingDecision;
    const confirmed = p.needs_networks ? parseNetworks(networks[p.finding_id] ?? "") : [];
    if (decision === "accepted" && p.needs_networks && confirmed.length === 0) {
      return {
        ok: false,
        reason: `Confirm the networks for ${p.rule_ref} before accepting it, or reject it.`,
      };
    }
    choices.push({
      finding_id: p.finding_id,
      kind: p.kind,
      ...(p.needs_networks ? { networks: confirmed } : {}),
    });
    approvals[p.finding_id] = {
      approval: decision,
      approver: name,
      decided_at: now.toISOString(),
    };
  }
  return { ok: true, selection: { choices, approvals } };
}
