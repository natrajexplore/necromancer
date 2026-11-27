import { expect, type Locator, type Page } from "@playwright/test";

/** The bundled synthetic sample the smoke tests use. */
export const SAMPLE = "pix-2006-hq";

export const stageTab = (page: Page, label: string): Locator =>
  page.getByRole("navigation", { name: "Stages of the ritual" }).getByRole("button", { name: new RegExp(`^\\d\\. ${label}`) });

/** Open a sample's tombstone from the graveyard. */
export async function openCrypt(page: Page, name = SAMPLE): Promise<void> {
  await page.goto("/");
  await page.getByRole("button", { name: new RegExp(`^${name} `) }).click();
  await expect(page.getByRole("heading", { level: 2, name })).toBeVisible();
}

export async function goToStage(page: Page, label: string): Promise<void> {
  await stageTab(page, label).click();
  await expect(page.getByRole("heading", { level: 2, name: new RegExp(`: ${label}$`) })).toBeVisible();
}

/** Resurrect, accept one proposal with a named approver, and prove the tightened artifact. */
export async function proveTightened(page: Page, findingId: string, approver: string): Promise<void> {
  await goToStage(page, "Resurrect");
  await page.getByRole("button", { name: "Resurrect", exact: true }).click();
  await page.getByRole("button", { name: `Accept ${findingId}` }).click();
  await page.getByLabel(/Approver/).fill(approver);
  await page.getByRole("button", { name: "Prove the tightened artifact" }).click();
  await expect(page.getByRole("heading", { name: "Tightened artifact (separate change)" })).toBeVisible();
  await expect(page.getByText(/Proof of Life: passed/)).toBeVisible();
}

/** Prove the baseline on the Proof of Life screen. */
export async function proveBaseline(page: Page): Promise<void> {
  await goToStage(page, "Proof of Life");
  await page.getByRole("button", { name: "Prove", exact: true }).click();
  await expect(page.getByText("The resurrected config behaved like the original on every flow checked.")).toBeVisible();
}

/** Run the gates on the Verdict screen and wait for the verdict. */
export async function runGates(page: Page, again = false): Promise<void> {
  await goToStage(page, "Verdict");
  await page.getByRole("button", { name: again ? "Run the gates again" : "Run the gates" }).click();
  await expect(page.getByRole("heading", { name: "Readiness verdict" })).toBeVisible();
}
