import { expect, test, type Locator, type Page } from "@playwright/test";

import { stageTab } from "./steps";

/**
 * Graveyard-ui task 8: the whole ritual works from the keyboard, focus is visible, and focus lands
 * somewhere sensible after each step. Controls are focused and activated with Enter or Space, the
 * way a keyboard user does it. Reduced motion is checked at the end.
 */
async function expectVisibleFocus(control: Locator): Promise<void> {
  await expect(control).toBeFocused();
  const outline = await control.evaluate((el) => {
    const style = getComputedStyle(el);
    return { style: style.outlineStyle, width: Number.parseFloat(style.outlineWidth) };
  });
  expect(outline.style).not.toBe("none");
  expect(outline.width).toBeGreaterThanOrEqual(2);
}

/** Focus a control by keyboard (Tab first, so that :focus-visible applies) and activate it. */
async function focusAndPress(page: Page, control: Locator, key: "Enter" | "Space"): Promise<void> {
  await page.keyboard.press("Tab");
  await control.focus();
  await expectVisibleFocus(control);
  await page.keyboard.press(key);
}

test("the whole ritual works from the keyboard, with visible focus and a sensible focus after each step", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to the graveyard" })).toBeFocused();

  // A tombstone opens with Enter and focus moves to its heading.
  await focusAndPress(page, page.getByRole("button", { name: /^pix-2006-hq / }), "Enter");
  await expect(page.getByRole("heading", { level: 2, name: "pix-2006-hq" })).toBeFocused();

  // Step tabs: Enter on each moves focus to the heading of the new screen.
  await focusAndPress(page, stageTab(page, "Autopsy"), "Enter");
  await expect(page.getByRole("heading", { level: 2, name: /: Autopsy$/ })).toBeFocused();
  await focusAndPress(page, page.getByRole("region", { name: "Rules and their findings" }), "Enter");

  await focusAndPress(page, stageTab(page, "Resurrect"), "Enter");
  await expect(page.getByRole("heading", { level: 2, name: /: Resurrect$/ })).toBeFocused();
  await focusAndPress(page, page.getByRole("button", { name: "Resurrect", exact: true }), "Enter");
  await expect(page.getByText(/lines? of PAN-OS candidate config/)).toBeFocused();

  // Accept buttons are toggles that Space operates.
  const accept = page.getByRole("button", { name: "Accept AUT-0008" });
  await focusAndPress(page, accept, "Space");
  await expect(accept).toHaveAttribute("aria-pressed", "true");
  await page.getByLabel(/Approver/).fill("A. Reviewer");
  await focusAndPress(page, page.getByRole("button", { name: "Prove the tightened artifact" }), "Enter");
  await expect(page.getByRole("heading", { name: "Tightened artifact (separate change)" })).toBeFocused();

  // Proof of Life: the Haunt checkbox takes Space, Prove takes Enter, focus lands on the result.
  await focusAndPress(page, stageTab(page, "Proof of Life"), "Enter");
  const haunt = page.getByRole("checkbox", { name: /Haunt it/ });
  await focusAndPress(page, haunt, "Space");
  await expect(haunt).toBeChecked();
  await focusAndPress(page, page.getByRole("button", { name: "Prove", exact: true }), "Enter");
  await expect(page.getByText("The resurrected config diverged from the original.")).toBeFocused();
  await focusAndPress(page, haunt, "Space");
  await expect(haunt).not.toBeChecked();

  // Verdict: run the gates, switch the judged artifact, reach the downloads.
  await focusAndPress(page, stageTab(page, "Verdict"), "Enter");
  await focusAndPress(page, page.getByRole("button", { name: "Run the gates" }), "Enter");
  await expect(page.getByRole("heading", { name: "Readiness verdict" })).toBeFocused();
  const tightened = page.getByRole("button", { name: "tightened (1 accepted)" });
  await focusAndPress(page, tightened, "Enter");
  await expect(tightened).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: "baseline", exact: true })).toHaveAttribute("aria-pressed", "false");
  for (const name of ["Download report (Markdown)", "Download baseline PAN-OS config (.txt)", "Download tightened PAN-OS config (.txt)"]) {
    const button = page.getByRole("button", { name });
    await page.keyboard.press("Tab");
    await button.focus();
    await expectVisibleFocus(button);
  }
});

test("the file input of the exhume zone shows its focus on the drop zone", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  const file = page.getByLabel("choose a file");
  await file.focus();
  await expect(file).toBeFocused();
  const outline = await page.getByTestId("drop-zone").evaluate((el) => getComputedStyle(el).outlineStyle);
  expect(outline).not.toBe("none");
});

test.describe("reduced motion", () => {
  test("nothing animates when the user prefers reduced motion", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "The graveyard" })).toBeVisible();
    const running = await page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").length);
    expect(running).toBe(0);
    await page.getByRole("button", { name: /^pix-2006-hq / }).click();
    await stageTab(page, "Resurrect").click();
    await page.getByRole("button", { name: "Resurrect", exact: true }).click();
    await expect(page.getByText(/lines? of PAN-OS candidate config/)).toBeVisible();
  });

  test.describe("when motion is allowed", () => {
    test.use({ reducedMotion: "no-preference" });
    test("the fog drifts, so the guard above is what stops it", async ({ page }) => {
      await page.goto("/");
      await expect(page.getByRole("heading", { name: "The graveyard" })).toBeVisible();
      const running = await page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").length);
      expect(running).toBeGreaterThan(0);
    });
  });
});
