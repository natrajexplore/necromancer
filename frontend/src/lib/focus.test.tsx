import { act, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { useFocusOnChange } from "./focus";

function Probe() {
  const [result, setResult] = useState<string | null>(null);
  const ref = useFocusOnChange<HTMLParagraphElement>(result);
  return (
    <div>
      <button type="button" onClick={() => setResult("done")}>
        Run
      </button>
      <button type="button" onClick={() => setResult(null)}>
        Clear
      </button>
      <p ref={ref} tabIndex={-1}>
        {result ?? "nothing yet"}
      </p>
    </div>
  );
}

describe("useFocusOnChange", () => {
  it("leaves focus alone on the first render and moves it when a result arrives", async () => {
    render(<Probe />);
    expect(document.body).toHaveFocus();
    await act(async () => screen.getByRole("button", { name: "Run" }).click());
    expect(screen.getByText("done")).toHaveFocus();
  });

  it("does not move focus when the value is cleared", async () => {
    render(<Probe />);
    await act(async () => screen.getByRole("button", { name: "Run" }).click());
    const clear = screen.getByRole("button", { name: "Clear" });
    clear.focus();
    await act(async () => clear.click());
    expect(clear).toHaveFocus();
  });
});
