import { afterEach, describe, expect, it, vi } from "vitest";

import { exhumeResult, json, mockApi } from "../test/api";
import { api, ApiError, MAX_CONFIG_BYTES } from "./client";

const CONFIG = "ASA Version 8.2(5)\nhostname crypt-asa\n";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("api client", () => {
  it("posts the config as JSON to /v1/exhume and returns the result", async () => {
    const fetchMock = mockApi({ "/v1/exhume": () => json(exhumeResult()) });
    const result = await api.exhume({ config: CONFIG, dialect: "asa" });
    expect(result.dialect).toBe("asa");
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe("/v1/exhume");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ config: CONFIG, dialect: "asa" });
    expect(new Headers(init?.headers).get("Content-Type")).toBe("application/json");
    expect(init?.credentials).toBe("omit");
  });

  it.each([
    ["autopsy", "/v1/autopsy"],
    ["resurrect", "/v1/resurrect"],
    ["prove", "/v1/prove"],
    ["grimoire", "/v1/grimoire"],
  ] as const)("calls %s at %s", async (name, path) => {
    const fetchMock = mockApi({ [path]: () => json({ api_version: "v1" }) });
    await api[name]({ config: CONFIG });
    expect(fetchMock.mock.calls[0]?.[0]).toBe(path);
  });

  it("sends prove options with the config", async () => {
    const fetchMock = mockApi({ "/v1/prove": () => json({ api_version: "v1" }) });
    await api.prove({ config: CONFIG, budget: 500, seed: 7, profile: "dev" });
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      config: CONFIG,
      budget: 500,
      seed: 7,
      profile: "dev",
    });
  });

  it("reads /healthz with a GET", async () => {
    const fetchMock = mockApi({ "/healthz": () => json({ status: "ok", version: "0.1.0", commit: "abc" }) });
    expect(await api.health()).toEqual({ status: "ok", version: "0.1.0", commit: "abc" });
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBeUndefined();
  });

  it("turns a structured error into an ApiError with its line number", async () => {
    mockApi({
      "/v1/exhume": () =>
        json({ code: "group-cycle", message: "object-group cycle: A -> B -> A", line_no: 9 }, 422),
    });
    const error = await api.exhume({ config: CONFIG }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 422, code: "group-cycle", lineNo: 9, isClientError: true });
    expect((error as ApiError).message).toBe("object-group cycle: A -> B -> A");
  });

  it("keeps the Retry-After of a rate limit", async () => {
    mockApi({
      "/v1/exhume": () => json({ code: "rate-limited", message: "too many requests" }, 429, { "Retry-After": "42" }),
    });
    await expect(api.exhume({ config: CONFIG })).rejects.toMatchObject({ code: "rate-limited", retryAfter: 42 });
  });

  it("handles an error response that is not JSON", async () => {
    mockApi({ "/v1/exhume": () => new Response("Bad Gateway", { status: 502, statusText: "Bad Gateway" }) });
    await expect(api.exhume({ config: CONFIG })).rejects.toMatchObject({
      status: 502,
      code: "http-502",
      isClientError: false,
    });
  });

  it("reports an unreachable API as a network error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(api.exhume({ config: CONFIG })).rejects.toMatchObject({ status: 0, code: "network" });
  });

  it("lets an aborted request stay an abort", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new DOMException("aborted", "AbortError")));
    await expect(api.exhume({ config: CONFIG })).rejects.toHaveProperty("name", "AbortError");
  });

  it("refuses a config over 2 MB (in bytes) before sending it", async () => {
    const fetchMock = mockApi({});
    const big = "é".repeat(MAX_CONFIG_BYTES / 2 + 1); // 2 bytes each in UTF-8
    await expect(api.exhume({ config: big })).rejects.toMatchObject({ status: 413, code: "too-large" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses VITE_API_BASE when the UI is deployed apart from the API", async () => {
    vi.stubEnv("VITE_API_BASE", "https://api.example.com/");
    const fetchMock = mockApi({ "/v1/exhume": () => json(exhumeResult()) });
    await api.exhume({ config: CONFIG });
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://api.example.com/v1/exhume");
  });
});
