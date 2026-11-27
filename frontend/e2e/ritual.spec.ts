import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { goToStage, openCrypt, proveBaseline, proveTightened, runGates, SAMPLE } from "./steps";

/**
 * Graveyard-ui task 9: smoke tests against the real engine and UI. Locators use roles, labels and
 * visible text. The engine's own numbers are checked here: they are the ones the golden flows and
 * the pix-2006-hq sample pin down.
 */
const SAMPLE_CONFIG = fileURLToPath(new URL("../../samples/dead-configs/pix-2006-hq.cfg", import.meta.url));

/** Click a download button and read what the browser saved. */
async function download(page: Page, name: string): Promise<{ name: string; text: string }> {
  const [saved] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name }).click()]);
  return { name: saved.suggestedFilename(), text: await readFile(await saved.path(), "utf8") };
}

test("the full ritual on pix-2006-hq, from exhume to a tightened GO and the downloads", async ({ page }) => {
  // Exhume: the sample parses with confidence 0.95 and every security-relevant line accounted for.
  await openCrypt(page);
  const details = page.getByRole("region", { name: SAMPLE });
  await expect(details).toContainText(/Detection confidence\s*0\.95/);
  await expect(details).toContainText(/Coverage\s*100%/);

  // Autopsy lists the critical insecure-service finding.
  await goToStage(page, "Autopsy");
  await expect(page.getByRole("region", { name: "Rules and their findings" })).toContainText("AUT-0008");

  // Resurrect, accept AUT-0008 with a named approver, and prove the tightened artifact.
  await proveTightened(page, "AUT-0008", "A. Reviewer");

  // Proof of Life of the baseline: all 16 hand-verified golden flows pass.
  await proveBaseline(page);
  await expect(page.getByText("16 of 16 passed")).toBeVisible();

  // Verdict: the baseline is NO-GO (G5 and G6 are open), judged on its own.
  await runGates(page);
  await expect(page.getByText("NO-GO", { exact: true })).toBeVisible();
  await expect(page.getByText(/for the baseline artifact/)).toBeVisible();
  await expect(page.getByText("G6: critical finding AUT-0008: insecure-service at outside_in#5", { exact: true })).toBeVisible();

  // Judge the tightened artifact: accept LED-0001 with an approver and a reason, then run again.
  await page.getByRole("button", { name: "tightened (1 accepted)" }).click();
  await expect(page.getByRole("heading", { name: "Pending ledger entries (tightened artifact)" })).toBeVisible();
  await page.getByLabel("Approver name (required)").fill("A. Reviewer");
  await page.getByLabel("Reason for LED-0001 (required)").fill("Management access is covered by the interface profile.");
  await page.getByRole("button", { name: "Accept LED-0001" }).click();
  await page.getByRole("button", { name: "Run the gates again" }).click();
  await expect(page.getByText("GO", { exact: true })).toBeVisible();
  await expect(page.getByText(/for the tightened artifact \(separate change\)/)).toBeVisible();
  await expect(page.getByText(/Baseline: NO-GO\. Tightened \(separate change\): GO\./)).toBeVisible();

  // The report downloads and names the input and both artifacts. The configs download apart.
  const report = await download(page, "Download report (Markdown)");
  expect(report.name).toBe("pix-2006-hq-grimoire.md");
  expect(report.text).toContain("# Grimoire: migration evidence report: pix-2006-hq (baseline and tightened artifacts)");
  expect(report.text).toContain("Readiness verdict, tightened artifact (a separate change): GO.");
  expect(report.text).toContain("Management access is covered by the interface profile.");

  const baseline = await download(page, "Download baseline PAN-OS config (.txt)");
  const tightened = await download(page, "Download tightened PAN-OS config (.txt)");
  const ledger = await download(page, "Download tightened ledger (.json)");
  expect([baseline.name, tightened.name, ledger.name]).toEqual([
    "pix-2006-hq-baseline-panos.txt",
    "pix-2006-hq-tightened-panos.txt",
    "pix-2006-hq-tightened-ledger.json",
  ]);
  expect(baseline.text).toMatch(/^set /);
  expect(tightened.text).not.toBe(baseline.text);
  expect(JSON.parse(ledger.text)).toEqual(expect.arrayContaining([expect.objectContaining({ id: "LED-0001" })]));
});

test("the haunted path: a failed proof with a counterexample, refused by gate and grimoire", async ({ page }) => {
  await openCrypt(page);
  await goToStage(page, "Proof of Life");
  await page.getByRole("checkbox", { name: /Haunt it/ }).check();
  await page.getByRole("button", { name: "Prove", exact: true }).click();

  await expect(page.getByRole("heading", { name: "The packet that refused to rest" })).toBeVisible();
  await expect(page.getByRole("img", { name: "Proof failed: the heartbeat stopped" })).toBeVisible();
  await expect(page.getByText("The resurrected config diverged from the original.")).toBeVisible();
  await expect(page.getByText(/Haunted: this result is for a deliberately broken candidate/)).toBeVisible();

  // A verdict or report never rests on a haunted candidate: the engine refuses it.
  const config = await readFile(SAMPLE_CONFIG, "utf8");
  for (const path of ["gate", "grimoire"]) {
    const response = await page.request.post(`/v1/${path}`, { data: { config, dialect: "pix", haunt: true, budget: 40 } });
    expect(response.status(), path).toBe(422);
    expect(await response.text()).toContain("haunt is only available for prove");
  }
});
