import { describe, expect, it } from "vitest";

import { dialectLabel, percent, plural } from "./format";

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

  it("pluralises counts", () => {
    expect(plural(1, "rule")).toBe("1 rule");
    expect(plural(11, "rule")).toBe("11 rules");
    expect(plural(2, "ACL")).toBe("2 ACLs");
  });
});
