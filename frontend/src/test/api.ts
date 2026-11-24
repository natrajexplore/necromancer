import { vi } from "vitest";

import type { ExhumeResult } from "../api/types";

/** A JSON response, as the backend sends it. */
export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

type Handler = (body: Record<string, unknown>) => Response | Promise<Response>;

/** Replace fetch with handlers keyed by path; returns the mock so tests can inspect calls. */
export function mockApi(routes: Record<string, Handler>) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input), "http://ui.test").pathname;
    const handler = routes[path];
    if (!handler) return json({ code: "not-found", message: `no mock for ${path}` }, 404);
    const body = typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : {};
    return handler(body);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

/** An exhume result shaped like the backend's, with synthetic (RFC 5737 / RFC 1918) content. */
export function exhumeResult(overrides: Partial<ExhumeResult> = {}): ExhumeResult {
  return {
    api_version: "v1",
    dialect: "asa",
    os_version: "9.8(4)",
    mode: "routed",
    address_space: "real",
    detection_confidence: 0.94,
    input_sha256: "0".repeat(64),
    interfaces: [
      { nameif: "outside", hw_name: "GigabitEthernet0/0", security_level: 0, address: "203.0.113.1/24" },
      { nameif: "inside", hw_name: "GigabitEthernet0/1", security_level: 100, address: "10.20.0.1/16" },
    ],
    acls: [{ name: "OUTSIDE_IN", rules: 6, classification: "" }],
    bindings: 1,
    nat_rules: 2,
    coverage: {
      total_lines: 120,
      counts: { migrated: 36, "not-policy": 49, "out-of-scope": 1, unparsed: 34 },
      security_relevant: 70,
      handled: 36,
      waived: 0,
      blocking: 34,
      ratio: 0.514,
    },
    unparsed: [
      {
        line_no: 41,
        text: "access-list OUTSIDE_IN extended permit tcp any6 host 2001:db8::10 eq https",
        reason: "ipv6",
        security_relevant: true,
        waived: false,
      },
      {
        line_no: 57,
        text: "object network WEB_FQDN",
        reason: "fqdn-object",
        security_relevant: true,
        waived: true,
      },
      { line_no: 90, text: "banner motd <redacted>", reason: "banner", security_relevant: false, waived: false },
    ],
    ...overrides,
  };
}
