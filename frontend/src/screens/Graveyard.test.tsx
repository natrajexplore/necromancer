import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { makeQueryClient } from "../api/hooks";
import { App } from "../App";
import { SAMPLES } from "../samples";
import { exhumeResult, json, mockApi } from "../test/api";

const HEALTH = { "/healthz": () => json({ status: "ok", version: "0.1.0", commit: "abc1234" }) };

function renderApp() {
  const user = userEvent.setup();
  render(
    <QueryClientProvider client={makeQueryClient()}>
      <App />
    </QueryClientProvider>,
  );
  return user;
}

const sample = SAMPLES.find((crypt) => crypt.name === "asa-9.8-dc");
if (!sample) throw new Error("the asa-9.8-dc sample is missing");

describe("Graveyard", () => {
  it("shows one tombstone per bundled sample, with its facts, and an 'Exhume your own' tombstone", () => {
    mockApi(HEALTH);
    renderApp();
    for (const crypt of SAMPLES) {
      const { sample: entry } = crypt;
      const tombstone = screen.getByRole("button", { name: new RegExp(`^${crypt.name}:`) });
      expect(tombstone).toHaveTextContent(entry.os_version);
      expect(tombstone).toHaveTextContent(`${entry.rules} rules`);
      expect(tombstone).toHaveTextContent(`died ${entry.died}`);
      expect(tombstone).toHaveAccessibleName(expect.stringContaining("fictional year"));
    }
    expect(screen.getByRole("heading", { name: "Exhume your own" })).toBeInTheDocument();
  });

  it("says that configs are not stored and that only synthetic configs belong on the demo", () => {
    mockApi(HEALTH);
    renderApp();
    const note = screen.getByRole("note");
    expect(note).toHaveTextContent("processed in memory and are not stored");
    expect(note).toHaveTextContent("use synthetic configs only");
  });

  it("exhumes a sample on click and lists its unquiet lines in plain sight", async () => {
    const fetchMock = mockApi({ ...HEALTH, "/v1/exhume": () => json(exhumeResult()) });
    const user = renderApp();
    await user.click(screen.getByRole("button", { name: /^asa-9\.8-dc:/ }));

    const details = await screen.findByRole("region", { name: "asa-9.8-dc" });
    await within(details).findByText("Cisco ASA 9.8(4)");
    const exhumeCall = fetchMock.mock.calls.find(([url]) => url === "/v1/exhume");
    expect(JSON.parse(String(exhumeCall?.[1]?.body))).toEqual({ config: sample.config });
    expect(details).toHaveTextContent("0.94");
    expect(details).toHaveTextContent("51.4%");
    expect(details).toHaveTextContent("36 of 70 security-relevant lines migrated or handled");

    const unquiet = within(details).getByRole("region", { name: /Unquiet lines/ });
    const table = within(unquiet).getByRole("table", { name: "Security-relevant lines that were not migrated" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("41");
    expect(rows[0]).toHaveTextContent("permit tcp any6 host 2001:db8::10");
    expect(rows[0]).toHaveTextContent("ipv6");
    expect(rows[0]).toHaveTextContent("blocks the verdict");
    expect(rows[1]).toHaveTextContent("waived");
    expect(within(unquiet).getByText(/Other lines not migrated \(1, not security-relevant\)/)).toBeInTheDocument();
  });

  it("explains the themed label in plain English, on hover and for screen readers", async () => {
    mockApi({ ...HEALTH, "/v1/exhume": () => json(exhumeResult()) });
    const user = renderApp();
    await user.click(screen.getByRole("button", { name: /^asa-9\.8-dc:/ }));
    const label = await screen.findByText("Unquiet lines");
    expect(label).toHaveAccessibleDescription(expect.stringContaining("blocks the readiness verdict"));
    expect(label).toHaveAttribute("tabindex", "0");
  });

  it("opens a tombstone from the keyboard", async () => {
    mockApi({ ...HEALTH, "/v1/exhume": () => json(exhumeResult()) });
    const user = renderApp();
    const tombstone = screen.getByRole("button", { name: /^asa-9\.8-dc:/ });
    tombstone.focus();
    await user.keyboard("{Enter}");
    expect(tombstone).toHaveAttribute("aria-pressed", "true");
    expect(await screen.findByRole("region", { name: "asa-9.8-dc" })).toBeInTheDocument();
  });

  it("adds a tombstone for a pasted config with dialect, confidence, coverage and unparsed counts", async () => {
    const fetchMock = mockApi({
      ...HEALTH,
      "/v1/exhume": () => json(exhumeResult({ dialect: "ios", os_version: "12.4", detection_confidence: 0.85 })),
    });
    const user = renderApp();
    await user.type(screen.getByLabelText("Or paste a config"), "version 12.4{enter}hostname tomb-edge-r1");
    await user.click(screen.getByRole("button", { name: "Exhume" }));

    const tombstone = await screen.findByRole("button", { name: /^Pasted config 1:/ });
    expect(tombstone).toHaveTextContent("Cisco IOS 12.4");
    expect(tombstone).toHaveTextContent("confidence 0.85");
    expect(tombstone).toHaveTextContent("coverage 51.4%");
    expect(tombstone).toHaveTextContent("3 not migrated, 2 security-relevant");
    expect(tombstone).toHaveAttribute("aria-pressed", "true");
    const details = await screen.findByRole("region", { name: "Pasted config 1" });
    expect(details).toHaveTextContent("Below 0.90");
    expect(fetchMock.mock.calls.filter(([url]) => url === "/v1/exhume")).toHaveLength(1);
    expect(screen.getByLabelText("Or paste a config")).toHaveValue("");
  });

  it("shows a parse error with its line number and adds no tombstone", async () => {
    mockApi({
      ...HEALTH,
      "/v1/exhume": () => json({ code: "group-cycle", message: "object-group cycle: A -> B -> A", line_no: 9 }, 422),
    });
    const user = renderApp();
    await user.type(screen.getByLabelText("Or paste a config"), "object-group network A");
    await user.click(screen.getByRole("button", { name: "Exhume" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("object-group cycle: A -> B -> A");
    expect(alert).toHaveTextContent("group-cycle at line 9");
    expect(screen.queryByRole("button", { name: /^Pasted config/ })).not.toBeInTheDocument();
  });

  it("exhumes a chosen file under its own name", async () => {
    mockApi({ ...HEALTH, "/v1/exhume": () => json(exhumeResult({ dialect: "pix", os_version: "6.3(5)" })) });
    const user = renderApp();
    const file = new File(["PIX Version 6.3(5)\n"], "branch-pix.cfg", { type: "text/plain" });
    await user.upload(screen.getByLabelText("choose a file"), file);
    expect(await screen.findByRole("button", { name: /^branch-pix\.cfg:/ })).toHaveTextContent("Cisco PIX 6.3(5)");
  });

  it("refuses a file over 2 MB without sending it", async () => {
    const fetchMock = mockApi(HEALTH);
    const user = renderApp();
    const file = new File([new Uint8Array(2 * 1024 * 1024 + 1)], "huge.cfg", { type: "text/plain" });
    await user.upload(screen.getByLabelText("choose a file"), file);
    expect(await screen.findByRole("alert")).toHaveTextContent("huge.cfg is larger than the 2 MB limit.");
    expect(fetchMock.mock.calls.some(([url]) => url === "/v1/exhume")).toBe(false);
  });

  it("shows which engine answered, or how to start it", async () => {
    mockApi(HEALTH);
    renderApp();
    expect(await screen.findByText(/Engine 0\.1\.0/)).toHaveTextContent("commit abc1234");
  });

  it("tells the user how to start the engine when it cannot be reached", async () => {
    mockApi({ "/healthz": () => Promise.reject(new TypeError("Failed to fetch")) });
    renderApp();
    await waitFor(() => expect(screen.getByText(/The engine is not reachable/)).toBeInTheDocument());
  });
});
