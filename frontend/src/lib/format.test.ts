import { describe, expect, it } from "vitest";

import { confidence, dialectLabel, percent, plural } from "./format";

describe("format", () => {
  it("names platforms in plain text", () => {
    expect(dialectLabel("pix", "6.3(5)")).toBe("Cisco PIX 6.3(5)");
    expect(dialectLabel("ios")).toBe("Cisco IOS");
  });

  it("rounds coverage down so an incomplete config never shows 100%", () => {
    expect(percent(1)).toBe("100%");
    expect(percent(0.9996)).toBe("99.9%");
    expect(percent(0.514)).toBe("51.4%");
    expect(percent(0)).toBe("0%");
  });

  it("cuts a detection confidence off at two decimals, so 0.895 never reads as 0.90", () => {
    expect(confidence(0.895)).toBe("0.89");
    expect(confidence(0.899)).toBe("0.89");
    expect(confidence(0.9)).toBe("0.90");
    expect(confidence(0.95)).toBe("0.95");
    expect(confidence(0.985)).toBe("0.98");
    expect(confidence(1)).toBe("1.00");
    expect(confidence(0)).toBe("0.00");
  });

  it("pluralises counts", () => {
    expect(plural(1, "rule")).toBe("1 rule");
    expect(plural(11, "rule")).toBe("11 rules");
    expect(plural(2, "ACL")).toBe("2 ACLs");
  });
});
