import { QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";

import { exhumeResult, json, mockApi } from "../test/api";
import { ApiError } from "./client";
import { makeQueryClient, shouldRetry, useAutopsy, useExhume, useGrimoire, useProve, type Crypt } from "./hooks";

const CRYPT: Crypt = { id: "sample:asa-9.8-dc", name: "asa-9.8-dc", config: "ASA Version 9.8(4)\n" };

function wrapper() {
  const client = makeQueryClient();
  return {
    client,
    Wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    ),
  };
}

describe("React Query bindings", () => {
  it("never retries a client error or an unreachable API, and retries a server error once", () => {
    expect(shouldRetry(0, new ApiError(422, "parse", "bad"))).toBe(false);
    expect(shouldRetry(0, new ApiError(429, "rate-limited", "slow down"))).toBe(false);
    expect(shouldRetry(0, new ApiError(0, "network", "down"))).toBe(false);
    expect(shouldRetry(0, new ApiError(500, "internal-error", "oops"))).toBe(true);
    expect(shouldRetry(1, new ApiError(500, "internal-error", "oops"))).toBe(false);
  });

  it("keys exhume by crypt id and caches it, so a second view sends no request", async () => {
    const fetchMock = mockApi({ "/v1/exhume": () => json(exhumeResult()) });
    const { client, Wrapper } = wrapper();
    const first = renderHook(() => useExhume(CRYPT), { wrapper: Wrapper });
    await waitFor(() => expect(first.result.current.isSuccess).toBe(true));
    expect(client.getQueryData(["exhume", CRYPT.id])).toMatchObject({ dialect: "asa" });
    const second = renderHook(() => useExhume(CRYPT), { wrapper: Wrapper });
    expect(second.result.current.data?.os_version).toBe("9.8(4)");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("re-sends the config text with each call (the backend keeps nothing)", async () => {
    const fetchMock = mockApi({ "/v1/autopsy": () => json({ api_version: "v1", findings: [] }) });
    const { Wrapper } = wrapper();
    const { result } = renderHook(() => useAutopsy({ ...CRYPT, dialect: "asa" }), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({ config: CRYPT.config, dialect: "asa" });
  });

  it("runs prove on demand with its options", async () => {
    const fetchMock = mockApi({ "/v1/prove": () => json({ api_version: "v1", passed: true }) });
    const { Wrapper } = wrapper();
    const { result } = renderHook(() => useProve(CRYPT), { wrapper: Wrapper });
    expect(fetchMock).not.toHaveBeenCalled();
    await result.current.mutateAsync({ budget: 50, seed: 3 });
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({ config: CRYPT.config, budget: 50, seed: 3 });
  });

  it("surfaces the grimoire's not-implemented answer as an ApiError", async () => {
    mockApi({ "/v1/grimoire": () => json({ code: "not-implemented", message: "not implemented yet" }, 501) });
    const { Wrapper } = wrapper();
    const { result } = renderHook(() => useGrimoire(CRYPT), { wrapper: Wrapper });
    await expect(result.current.mutateAsync()).rejects.toMatchObject({ status: 501, code: "not-implemented" });
  });
});
