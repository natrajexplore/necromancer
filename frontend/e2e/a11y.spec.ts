import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { goToStage, openCrypt, proveBaseline, proveTightened, runGates } from "./steps";

/**
 * Graveyard-ui task 8: axe on the graveyard and the five screens of the ritual. No rule is
 * disabled. Serious and critical violations fail the test, and the message names each one.
 */
async function expectNoSeriousViolations(page: Page, where: string): Promise<void> {
  const results = await new AxeBuilder({ page }).analyze();
  const blocking = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  const text = blocking
    .map((v) => `${v.id} (${v.impact}): ${v.help}\n${v.nodes.map((n) => `  ${n.target.join(" ")}\n  ${n.failureSummary ?? ""}`).join("\n")}`)
    .join("\n");
  expect(blocking, `${where}\n${text}`).toEqual([]);
}

// A small synthetic ASA config (RFC 5737 and RFC 1918 addresses only).
const LAB_CONFIG = [
  "ASA Version 8.2(5)",
  "hostname lab-fw",
  "interface Ethernet0/0",
  " nameif outside",
  " security-level 0",
  " ip address 198.51.100.1 255.255.255.0",
  "interface Ethernet0/1",
  " nameif inside",
  " security-level 100",
  " ip address 10.0.0.1 255.255.255.0",
  "access-list IN_OUT extended permit tcp 10.0.0.0 255.255.255.0 any eq 443",
  "access-list IN_OUT extended deny ip any any log",
  "access-group IN_OUT in interface inside",
  "",
].join("\n");

test.describe("accessibility (axe)", () => {
  test("the graveyard", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "The graveyard" })).toBeVisible();
    await expect(page.getByText(/Engine .* \(commit/)).toBeVisible();
    await expectNoSeriousViolations(page, "graveyard");
  });

  test("the five screens of the ritual", async ({ page }) => {
    await openCrypt(page);
    await expect(page.getByText("Detection confidence")).toBeVisible();
    await expectNoSeriousViolations(page, "exhume");

    await goToStage(page, "Autopsy");
    await expect(page.getByRole("region", { name: "Rules and their findings" })).toBeVisible();
    await expectNoSeriousViolations(page, "autopsy");

    await proveTightened(page, "AUT-0008", "A. Reviewer");
    await expectNoSeriousViolations(page, "resurrect, with a proved tightened artifact");

    await proveBaseline(page);
    await expectNoSeriousViolations(page, "proof of life, passed");

    await page.getByRole("checkbox", { name: /Haunt it/ }).check();
    await page.getByRole("button", { name: "Prove", exact: true }).click();
    await expect(page.getByRole("heading", { name: "The packet that refused to rest" })).toBeVisible();
    await expectNoSeriousViolations(page, "proof of life, haunted (counterexample)");

    await runGates(page);
    await expect(page.getByRole("heading", { name: "Runbook" })).toBeVisible();
    await expectNoSeriousViolations(page, "verdict, baseline");

    await page.getByRole("button", { name: /^tightened \(1 accepted\)$/ }).click();
    await expectNoSeriousViolations(page, "verdict, tightened");
  });

  test("an uploaded config shows its tombstone and passes axe", async ({ page }) => {
    await page.goto("/");
    await page.getByLabel("Or paste a config").fill(LAB_CONFIG);
    await page.getByRole("button", { name: "Exhume", exact: true }).click();
    await expect(page.getByRole("button", { name: /^Pasted config 1 / })).toBeVisible();
    await expectNoSeriousViolations(page, "graveyard with an uploaded tombstone");
  });
});
