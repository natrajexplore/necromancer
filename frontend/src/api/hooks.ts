/**
 * React Query bindings. Queries are keyed by crypt id (design: "React Query keyed by cryptId").
 * The config text lives only in client memory and is re-sent on every call: the backend is
 * stateless and stores nothing.
 */
import { QueryClient, queryOptions, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError } from "./client";
import type { DialectName, ProveRequest, TightenedResult, TighteningSelection } from "./types";

/** One config in the graveyard: a bundled sample or one the user exhumed. */
export interface Crypt {
  id: string; // "sample:<name>" or "upload:<n>"
  name: string;
  config: string;
  dialect?: DialectName;
}

function request(crypt: Crypt) {
  return crypt.dialect ? { config: crypt.config, dialect: crypt.dialect } : { config: crypt.config };
}

/**
 * Bundled samples name themselves, so the engine can run their golden flows without the UI
 * sending them. Only prove and grimoire use the golden flows. An upload has none.
 */
function withSample(crypt: Crypt) {
  const prefix = "sample:";
  return crypt.id.startsWith(prefix) ? { ...request(crypt), sample: crypt.id.slice(prefix.length) } : request(crypt);
}

/** Never retry a 4xx (same input, same answer) or a rate limit; retry other failures once. */
export function shouldRetry(failures: number, error: unknown): boolean {
  if (error instanceof ApiError && (error.isClientError || error.status === 0)) return false;
  return failures < 1;
}

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: shouldRetry, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  });
}

// Results depend only on the config text, which never changes for a crypt: cache them for good.
const forever = { staleTime: Infinity, gcTime: Infinity } as const;

export const exhumeQuery = (crypt: Crypt) =>
  queryOptions({
    queryKey: ["exhume", crypt.id],
    queryFn: ({ signal }) => api.exhume(request(crypt), signal),
    ...forever,
  });

export const autopsyQuery = (crypt: Crypt) =>
  queryOptions({
    queryKey: ["autopsy", crypt.id],
    queryFn: ({ signal }) => api.autopsy(request(crypt), signal),
    ...forever,
  });

export const resurrectQuery = (crypt: Crypt) =>
  queryOptions({
    queryKey: ["resurrect", crypt.id],
    queryFn: ({ signal }) => api.resurrect(request(crypt), signal),
    ...forever,
  });

export const healthQuery = () =>
  queryOptions({
    queryKey: ["health"],
    queryFn: ({ signal }) => api.health(signal),
    staleTime: 60_000,
    retry: false,
  });

export function useExhume(crypt: Crypt) {
  return useQuery(exhumeQuery(crypt));
}

export function useAutopsy(crypt: Crypt) {
  return useQuery(autopsyQuery(crypt));
}

export function useResurrect(crypt: Crypt) {
  return useQuery(resurrectQuery(crypt));
}

/** Where the tightened artifact of a crypt lives once proved, so the Verdict screen can offer it. */
export const tightenedKey = (crypt: Crypt) => ["tightened", crypt.id] as const;

/**
 * Tighten and prove on demand. The baseline answer in the "resurrect" cache is never touched:
 * the tightened artifact is stored under its own key (governance R1).
 */
export function useTighten(crypt: Crypt) {
  const client = useQueryClient();
  return useMutation({
    mutationKey: ["tighten", crypt.id],
    mutationFn: async (tightening: TighteningSelection) => {
      const result = await api.resurrect({ ...withSample(crypt), tightening, profile: "dev" });
      if (!result.tightened) throw new Error("the engine returned no tightened artifact");
      return result.tightened;
    },
    onSuccess: (tightened) => client.setQueryData(tightenedKey(crypt), tightened),
  });
}

/** The last proved tightened artifact for this crypt, if any. It never fetches. */
export function useTightened(crypt: Crypt) {
  return useQuery<TightenedResult | null>({
    queryKey: tightenedKey(crypt),
    queryFn: () => null,
    enabled: false,
    staleTime: Infinity,
    gcTime: Infinity,
  });
}

export function useHealth() {
  return useQuery(healthQuery());
}

/** Proof of Life is expensive and option-dependent, so it runs on demand. */
export function useProve(crypt: Crypt) {
  return useMutation({
    mutationKey: ["prove", crypt.id],
    mutationFn: (options: Omit<ProveRequest, "config" | "dialect">) =>
      api.prove({ ...withSample(crypt), ...options }),
  });
}

/** The Grimoire (report + verdict) also runs on demand. */
export function useGrimoire(crypt: Crypt) {
  return useMutation({
    mutationKey: ["grimoire", crypt.id],
    mutationFn: () => api.grimoire(withSample(crypt)),
  });
}
