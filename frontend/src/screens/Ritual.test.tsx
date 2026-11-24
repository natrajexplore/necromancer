import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { makeQueryClient, type Crypt } from "../api/hooks";
import type {
  AutopsyResult,
  Counterexample,
  Finding,
  GrimoireResult,
  LedgerEntry,
  ProveResult,
  ResurrectResult,
} from "../api/types";
import { SAMPLES } from "../samples";
import { exhumeResult, json, mockApi } from "../test/api";
import { reducedMotion } from "../test/setup";
import { Autopsy } from "./Autopsy";
import { ProofOfLife } from "./ProofOfLife";
import { Resurrection } from "./Resurrection";
import { Verdict } from "./Verdict";

const UPLOAD: Crypt = { id: "upload:1", name: "edge.cfg", config: "hostname synthetic\n" };
const SAMPLE = SAMPLES[0] as Crypt;

function renderWith(ui: ReactElement) {
  return render(<QueryClientProvider client={makeQueryClient()}>{ui}</QueryClientProvider>);
}

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "AUT-0001",
    type: "shadowed",
    severity: "medium",
    rule_ref: "IN#3",
    related: ["IN#1"],
    source_line: 12,
    zone: "",
    explanation: "IN#3 can never match: IN#1 comes earlier.",
    recommendation: "Remove IN#3.",
    label: "Buried Rule",
    verified: true,
    ...overrides,
  };
}

const FINDINGS: Finding[] = [
  finding({}),
  finding({ id: "AUT-0002", type: "insecure-service", severity: "critical", rule_ref: "IN#2", related: [], label: "Open Grave" }),
  finding({ id: "AUT-0003", type: "unfiltered-interface", severity: "high", rule_ref: "interface:dmz", related: [], zone: "dmz", label: "Unguarded Gate" }),
];

const AUTOPSY: AutopsyResult = {
  api_version: "v1",
  dialect: "asa",
  findings: FINDINGS,
  by_severity: { critical: 1, high: 1, medium: 1 },
  by_type: { shadowed: 1, "insecure-service": 1, "unfiltered-interface": 1 },
};

const PANOS = [
  "set network interface ethernet ethernet1/1 layer3 ip 203.0.113.1/24",
  "set zone untrust network layer3 ethernet1/1",
].join("\n");

function entry(overrides: Partial<LedgerEntry>): LedgerEntry {
  return {
    id: "LED-0001",
    class: "to-the-box",
    reason: "Management traffic is governed by the management profile.",
    affected: "tcp any -> 203.0.113.1/32",
    context: "outside:in",
    old_action: "permit",
    new_action: "deny",
    finding_ref: "",
    approval: "pending",
    approver: "",
    decided_at: "",
    informational: false,
    ...overrides,
  };
}

const RESURRECT: ResurrectResult = {
  api_version: "v1",
  dialect: "asa",
  config: PANOS,
  config_lines: 2,
  ledger: [entry({}), entry({ id: "LED-0002", class: "tightening", reason: "Close telnet from outside." })],
  unsupported: [],
  notes: [],
  blocking: [],
};

afterEach(() => vi.useRealTimers());

describe("Autopsy", () => {
  const routes = {
    "/v1/exhume": () =>
      json(
        exhumeResult({
          acls: [{ name: "IN", rules: 3, classification: "" }],
          interfaces: [
            { nameif: "outside", hw_name: "Gi0/0", security_level: 0, address: "203.0.113.1/24" },
            { nameif: "dmz", hw_name: "Gi0/2", security_level: 50, address: "10.2.0.1/24" },
          ],
        }),
      ),
    "/v1/autopsy": () => json(AUTOPSY),
    "/v1/resurrect": () => json(RESURRECT),
  };

  it("lists the rules in order with ghost badges and plain-English tooltips", async () => {
    mockApi(routes);
    renderWith(<Autopsy crypt={UPLOAD} />);
    const region = await screen.findByRole("region", { name: "Rules and their findings" });
    const rows = within(region).getAllByRole("listitem");
    expect(rows.map((row) => within(row).getByText(/^IN#\d$/).textContent)).toEqual(["IN#1", "IN#2", "IN#3"]);
    expect(within(rows[2] as HTMLElement).getByText("Buried Rule")).toBeInTheDocument();
    expect(within(rows[2] as HTMLElement).getByRole("tooltip")).toHaveTextContent("can never match");
    expect(within(rows[1] as HTMLElement).getByText(/insecure service, critical/)).toBeInTheDocument();
  });

  it("highlights the rule that shadows the chosen rule", async () => {
    mockApi(routes);
    const user = userEvent.setup();
    renderWith(<Autopsy crypt={UPLOAD} />);
    const region = await screen.findByRole("region", { name: "Rules and their findings" });
    const rows = within(region).getAllByRole("listitem");
    expect(rows[0]).toHaveAttribute("data-related", "false");
    await user.click(within(rows[2] as HTMLElement).getByRole("button"));
    expect(rows[0]).toHaveAttribute("data-related", "true");
    expect(rows[1]).toHaveAttribute("data-related", "false");
  });

  it("filters by severity and by type", async () => {
    mockApi(routes);
    const user = userEvent.setup();
    renderWith(<Autopsy crypt={UPLOAD} />);
    const region = await screen.findByRole("region", { name: "Rules and their findings" });
    await user.selectOptions(screen.getByLabelText("Severity"), "critical");
    expect(within(region).getAllByRole("listitem")).toHaveLength(1);
    await user.selectOptions(screen.getByLabelText("Severity"), "");
    await user.selectOptions(screen.getByLabelText("Finding type"), "shadowed");
    expect(within(region).getAllByRole("listitem")).toHaveLength(1);
    expect(within(region).getByText("IN#3")).toBeInTheDocument();
  });

  it("maps interfaces to zones and marks the unfiltered one", async () => {
    mockApi(routes);
    renderWith(<Autopsy crypt={UPLOAD} />);
    const table = await screen.findByRole("table", { name: /zones they map to/ });
    const outside = within(table).getByRole("row", { name: /outside/ });
    expect(outside).toHaveTextContent("untrust");
    expect(outside).toHaveTextContent("ACL bound");
    expect(within(table).getByRole("row", { name: /dmz/ })).toHaveTextContent("Unfiltered");
  });

  it("lists findings that belong to no rule", async () => {
    mockApi(routes);
    renderWith(<Autopsy crypt={UPLOAD} />);
    const section = await screen.findByRole("region", { name: "Findings about more than one rule" });
    expect(section).toHaveTextContent("interface:dmz");
  });
});

describe("Resurrection", () => {
  const routes = { "/v1/resurrect": () => json(RESURRECT) };

  it("plays the rise for about 2.4 s, then shows the candidate beside the original", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockApi(routes);
    renderWith(<Resurrection crypt={SAMPLE} />);
    fireEvent.click(screen.getByRole("button", { name: "Resurrect" }));
    expect(screen.getByTestId("rise")).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2300);
    });
    expect(screen.getByTestId("rise")).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200);
    });
    expect(screen.queryByTestId("rise")).not.toBeInTheDocument();
    expect(screen.getByText(/ethernet1\/1 layer3 ip/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: `Original: ${SAMPLE.name}` })).toBeInTheDocument();
  });

  it("skips the animation under reduced motion", async () => {
    reducedMotion.matches = true;
    mockApi(routes);
    renderWith(<Resurrection crypt={SAMPLE} />);
    fireEvent.click(screen.getByRole("button", { name: "Resurrect" }));
    expect(await screen.findByText(/ethernet1\/1 layer3 ip/)).toBeInTheDocument();
    expect(screen.queryByTestId("rise")).not.toBeInTheDocument();
  });

  it("does not echo the original text of an uploaded config", async () => {
    reducedMotion.matches = true;
    mockApi(routes);
    renderWith(<Resurrection crypt={UPLOAD} />);
    fireEvent.click(screen.getByRole("button", { name: "Resurrect" }));
    await screen.findByText(/ethernet1\/1 layer3 ip/);
    expect(screen.queryByText(/hostname synthetic/)).not.toBeInTheDocument();
    expect(screen.getByText(/does not return a redacted copy/)).toBeInTheDocument();
  });

  it("updates the live ledger when a remediation is accepted or rejected", async () => {
    reducedMotion.matches = true;
    mockApi(routes);
    const user = userEvent.setup();
    renderWith(<Resurrection crypt={SAMPLE} />);
    await user.click(screen.getByRole("button", { name: "Resurrect" }));
    const status = await screen.findByText(/2 entries: 2 pending, 0 accepted, 0 rejected/);
    await user.click(screen.getByRole("button", { name: "Accept LED-0002" }));
    expect(status).toHaveTextContent("1 pending, 1 accepted, 0 rejected");
    await user.click(screen.getByRole("button", { name: "Reject LED-0002" }));
    expect(status).toHaveTextContent("1 pending, 0 accepted, 1 rejected");
    await user.click(screen.getByRole("button", { name: "Reject LED-0002" }));
    expect(status).toHaveTextContent("2 pending");
  });
});

function counterexample(): Counterexample {
  const flow = { src: "198.51.100.7", dst: "10.1.0.5", proto: 6, src_port: 40000, dst_port: 443, icmp_type: null, established: false };
  return {
    source: "search",
    context: "outside:in",
    flow,
    panos_flow: flow,
    original: { action: "deny", rule_id: "IN#4", to_zone: "inside", reason: "matched IN#4" },
    resurrected: { action: "permit", rule_id: "rule-2", to_zone: "inside", reason: "matched rule-2" },
    original_zone: "inside",
    expected_action: "deny",
    ledger_ids: [],
    reason: "The original denies this flow and the candidate permits it.",
    vector_id: "",
  };
}

function proveResult(passed: boolean, extra: Partial<ProveResult> = {}): ProveResult {
  const side = { rules: 4, hit: 3, percent: 75, unhit: [] };
  const ce = passed ? null : counterexample();
  return {
    api_version: "v1",
    dialect: "asa",
    passed,
    ledger_entries: 0,
    blocking_lines: 0,
    proof: {
      passed,
      seed: 7,
      budget: 500,
      golden: { total: 5, passed: 5, failures: [] },
      contexts: [
        { context: "outside:in", implicit: false, examples: 500, passed, original: side, resurrected: side, ledger_covered: 0, counterexample: ce },
        { context: "dmz:in", implicit: true, examples: 500, passed: true, original: side, resurrected: side, ledger_covered: 0, counterexample: null },
      ],
      counterexample: ce,
    },
    ...extra,
  };
}

describe("Proof of Life", () => {
  it("shows a steady heartbeat, the stats and the per-context results", async () => {
    mockApi({ "/v1/prove": () => json(proveResult(true)) });
    const user = userEvent.setup();
    renderWith(<ProofOfLife crypt={UPLOAD} />);
    await user.click(screen.getByRole("button", { name: "Prove" }));
    expect(await screen.findByRole("img", { name: /heartbeat is steady/ })).toBeInTheDocument();
    expect(screen.getByText("1,000")).toBeInTheDocument();
    expect(screen.getByText("5 of 5 passed")).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /dmz:in/ })).toHaveTextContent("implicit");
    expect(screen.queryByText("The packet that refused to rest")).not.toBeInTheDocument();
  });

  it("shows the packet that refused to rest when the proof fails", async () => {
    mockApi({ "/v1/prove": () => json(proveResult(false)) });
    const user = userEvent.setup();
    renderWith(<ProofOfLife crypt={UPLOAD} />);
    await user.click(screen.getByRole("button", { name: "Prove" }));
    const card = await screen.findByRole("article");
    expect(screen.getByRole("img", { name: /heartbeat stopped/ })).toBeInTheDocument();
    expect(card).toHaveTextContent("tcp 198.51.100.7:40000 -> 10.1.0.5:443");
    expect(card).toHaveTextContent("outside:in");
    expect(card).toHaveTextContent("IN#4");
    expect(card).toHaveTextContent("rule-2");
    expect(card).toHaveTextContent("Denied");
    expect(card).toHaveTextContent("Permitted");
  });

  it("sends haunt only when the toggle is on, and says so when the engine ignored it", async () => {
    const fetchMock = mockApi({ "/v1/prove": () => json(proveResult(true)) });
    const user = userEvent.setup();
    renderWith(<ProofOfLife crypt={UPLOAD} />);
    await user.click(screen.getByRole("button", { name: "Prove" }));
    await screen.findByRole("img", { name: /steady/ });
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).not.toHaveProperty("haunt");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await user.click(screen.getByRole("checkbox", { name: /Haunt it/ }));
    await user.click(screen.getByRole("button", { name: "Prove" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("did not apply it");
    expect(JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body))).toMatchObject({ haunt: true });
  });

  it("shows the counterexample card, and no 'ignored' alert, when the engine answers haunted", async () => {
    const fetchMock = mockApi({ "/v1/prove": () => json(proveResult(false, { haunted: true })) });
    const user = userEvent.setup();
    renderWith(<ProofOfLife crypt={UPLOAD} />);
    await user.click(screen.getByRole("checkbox", { name: /Haunt it/ }));
    await user.click(screen.getByRole("button", { name: "Prove" }));
    expect(await screen.findByText(/deliberately broken candidate. Do not use it/)).toBeInTheDocument();
    const card = await screen.findByRole("article");
    expect(within(card).getByRole("heading", { name: /The packet that refused to rest/ })).toBeInTheDocument();
    expect(card).toHaveTextContent("tcp 198.51.100.7:40000 -> 10.1.0.5:443");
    expect(card).toHaveTextContent("Original config says");
    expect(card).toHaveTextContent("Resurrected config says");
    expect(screen.getByRole("img", { name: /heartbeat stopped/ })).toBeInTheDocument();
    expect(screen.queryByText(/did not apply it/)).not.toBeInTheDocument();
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toMatchObject({ haunt: true });
  });
});

const MARKDOWN = `# Grimoire

## 9. Runbook

### Verification commands on the target (PAN-OS)

| ID | Command | Expected result |
| --- | --- | --- |
| V1 | test security-policy-match from outside source 198.51.100.7 | allow |

## 10. Appendix
`;

const GRIMOIRE: GrimoireResult = {
  api_version: "v1",
  dialect: "asa",
  verdict: {
    value: "NO-GO",
    gates: [
      { gate: "G1", status: "pass", checks: [{ id: "sha", ok: true, severity: "error", detail: "recorded" }], blocking_reasons: [] },
      { gate: "G2", status: "fail", checks: [{ id: "coverage", ok: false, severity: "error", detail: "34 security-relevant lines are unparsed" }], blocking_reasons: ["34 lines"] },
    ],
    blocking_reasons: ["G2: 34 security-relevant lines are unparsed"],
    conditions: [],
    waivers_used: [],
    notes: [],
  },
  coverage: exhumeResult().coverage,
  proof_passed: true,
  examples_per_context: 5000,
  seed: 1,
  profile: "ci",
  golden_total: 3,
  golden_passed: 3,
  markdown: MARKDOWN,
  html: "<html><body>report</body></html>",
  body_sha256: "0".repeat(64),
};

describe("Verdict and Grimoire", () => {
  const routes = { "/v1/grimoire": () => json(GRIMOIRE), "/v1/resurrect": () => json(RESURRECT) };

  it("shows the verdict and the gate table first, in plain language", async () => {
    mockApi(routes);
    const user = userEvent.setup();
    renderWith(<Verdict crypt={UPLOAD} />);
    await user.click(screen.getByRole("button", { name: "Run the gates" }));
    const verdict = await screen.findByRole("heading", { name: "Readiness verdict" });
    const gates = screen.getByRole("table", { name: "Gates G1 to G6" });
    const runbook = screen.getByRole("heading", { name: "Runbook" });
    expect(screen.getByText("NO-GO")).toBeInTheDocument();
    expect(screen.getByText("G2: 34 security-relevant lines are unparsed", { selector: "li" })).toBeInTheDocument();
    expect(within(gates).getByRole("row", { name: /G2 Fail/ })).toBeInTheDocument();
    expect(verdict.compareDocumentPosition(gates) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(gates.compareDocumentPosition(runbook) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.queryByText(/compliant/i)).not.toBeInTheDocument();
  });

  it("copies a runbook command", async () => {
    mockApi(routes);
    const user = userEvent.setup();
    renderWith(<Verdict crypt={UPLOAD} />);
    const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
    await user.click(screen.getByRole("button", { name: "Run the gates" }));
    await user.click(await screen.findByRole("button", { name: /^Copy V1 of Verification/ }));
    expect(writeText).toHaveBeenCalledWith("test security-policy-match from outside source 198.51.100.7");
    expect(await screen.findByText("Copied")).toBeInTheDocument();
  });

  it("downloads the report and the baseline config", async () => {
    mockApi(routes);
    const created: Blob[] = [];
    Object.assign(URL, {
      createObjectURL: (blob: Blob) => (created.push(blob), "blob:test"),
      revokeObjectURL: () => undefined,
    });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const user = userEvent.setup();
    renderWith(<Verdict crypt={UPLOAD} />);
    await user.click(screen.getByRole("button", { name: "Run the gates" }));
    const baseline = await screen.findByRole("button", { name: /baseline PAN-OS config/ });
    await vi.waitFor(() => expect(baseline).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Download report (Markdown)" }));
    await user.click(baseline);
    expect(click).toHaveBeenCalledTimes(2);
    expect(await created[0]?.text()).toBe(MARKDOWN);
    expect(await created[1]?.text()).toBe(PANOS);
    expect(screen.getByText(/No tightened config is offered/)).toBeInTheDocument();
    expect(screen.getByText(/considered exposed and rotated/)).toBeInTheDocument();
  });
});
