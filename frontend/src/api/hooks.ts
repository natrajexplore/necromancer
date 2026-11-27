/**
 * React Query bindings. Queries are keyed by crypt id (design: "React Query keyed by cryptId").
 * The config text lives only in client memory and is re-sent on every call: the backend is
 * stateless and stores nothing.
 */
import { QueryClient, queryOptions, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError } from "./client";
import type {
  DialectName,
  GrimoireRequest,
  LedgerDecision,
  ProveRequest,
  TightenedResult,
  TighteningSelection,
} from "./types";

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

/** The selection the stored tightened artifact was built from, so the gates can rebuild it. */
export const selectionKey = (crypt: Crypt) => ["tightening-selection", crypt.id] as const;

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
    onSuccess: (tightened, selection) => {
      client.setQueryData(tightenedKey(crypt), tightened);
      client.setQueryData(selectionKey(crypt), selection);
    },
  });
}

/** The selection behind the last tightened artifact for this crypt, if any. It never fetches. */
export function useTighteningSelection(crypt: Crypt) {
  return useQuery<TighteningSelection | null>({
    queryKey: selectionKey(crypt),
    queryFn: () => null,
    enabled: false,
    staleTime: Infinity,
    gcTime: Infinity,
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

/** What a gate run sends besides the config: the tightening to judge and the ledger decisions. */
export interface GateOptions {
  tightening?: TighteningSelection | null;
  decisions?: Record<string, LedgerDecision>;
}

/** The report names the input, never a placeholder. The API caps the label at 120 characters. */
function inputName(crypt: Crypt): string {
  return crypt.name.slice(0, 120);
}

/**
 * The Grimoire (report + verdict) also runs on demand. The decisions travel as the sidecar of this
 * one request: the engine uses them for the answer and stores nothing.
 */
export function useGrimoire(crypt: Crypt) {
  return useMutation({
    mutationKey: ["grimoire", crypt.id],
    mutationFn: (options: GateOptions = {}) => {
      const body: GrimoireRequest = { ...withSample(crypt), name: inputName(crypt) };
      if (options.tightening) body.tightening = options.tightening;
      if (options.decisions && Object.keys(options.decisions).length > 0) {
        body.sidecar = { ledger_decisions: options.decisions };
      }
      return api.grimoire(body);
    },
  });
}
