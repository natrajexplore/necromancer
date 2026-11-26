/**
 * Thin fetch client for the necro v1 API. In development Vite proxies `/v1` and `/healthz` to
 * http://localhost:8000 (vite.config.ts); a deployed UI sets `VITE_API_BASE` to the API origin.
 *
 * Every failure becomes an ApiError carrying the backend's structured `{code, message, line_no?}`,
 * so screens can show the line a parse error points at.
 */
import type {
  AutopsyResult,
  ConfigRequest,
  ErrorBody,
  ExhumeResult,
  GrimoireResult,
  Health,
  ProveRequest,
  ProveResult,
  ResurrectRequest,
  ResurrectResult,
} from "./types";

/** The same 2 MB limit the backend enforces, checked before uploading. */
export const MAX_CONFIG_BYTES = 2 * 1024 * 1024;

export class ApiError extends Error {
  readonly status: number; // HTTP status, 0 when the API could not be reached
  readonly code: string;
  readonly lineNo: number | undefined;
  readonly retryAfter: number | undefined; // seconds, on 429

  constructor(
    status: number,
    code: string,
    message: string,
    lineNo?: number,
    retryAfter?: number,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.lineNo = lineNo;
    this.retryAfter = retryAfter;
  }

  /** A 4xx: retrying the same request gives the same answer. */
  get isClientError(): boolean {
    return this.status >= 400 && this.status < 500;
  }
}

function apiBase(): string {
  const base: unknown = import.meta.env.VITE_API_BASE;
  return typeof base === "string" ? base.replace(/\/+$/, "") : "";
}

function isErrorBody(value: unknown): value is ErrorBody {
  if (typeof value !== "object" || value === null) return false;
  const body = value as Record<string, unknown>;
  return typeof body.code === "string" && typeof body.message === "string";
}

async function toApiError(response: Response): Promise<ApiError> {
  const header = response.headers.get("Retry-After");
  const retryAfter = header && /^\d+$/.test(header) ? Number(header) : undefined;
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (isErrorBody(body)) {
    const lineNo = typeof body.line_no === "number" ? body.line_no : undefined;
    return new ApiError(response.status, body.code, body.message, lineNo, retryAfter);
  }
  const message = `the API answered ${response.status} ${response.statusText}`.trim();
  return new ApiError(response.status, `http-${response.status}`, message, undefined, retryAfter);
}

async function request<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${apiBase()}${path}`, {
      ...init,
      headers: { Accept: "application/json", ...init.headers },
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(
      0,
      "network",
      "The necro API could not be reached. Start the backend on port 8000 and try again.",
    );
  }
  if (!response.ok) throw await toApiError(response);
  return (await response.json()) as T;
}

function checkSize(config: string): void {
  if (new TextEncoder().encode(config).length > MAX_CONFIG_BYTES) {
    throw new ApiError(413, "too-large", "The config is larger than the 2 MB limit.");
  }
}

// async, so that a size refusal is a rejected promise like every other failure
async function post<T>(path: string, body: ConfigRequest, signal?: AbortSignal): Promise<T> {
  checkSize(body.config);
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: signal ?? null,
  });
}

export const api = {
  health: (signal?: AbortSignal) => request<Health>("/healthz", { signal: signal ?? null }),
  exhume: (body: ConfigRequest, signal?: AbortSignal) =>
    post<ExhumeResult>("/v1/exhume", body, signal),
  autopsy: (body: ConfigRequest, signal?: AbortSignal) =>
    post<AutopsyResult>("/v1/autopsy", body, signal),
  resurrect: (body: ResurrectRequest, signal?: AbortSignal) =>
    post<ResurrectResult>("/v1/resurrect", body, signal),
  prove: (body: ProveRequest, signal?: AbortSignal) =>
    post<ProveResult>("/v1/prove", body, signal),
  grimoire: (body: ProveRequest, signal?: AbortSignal) =>
    post<GrimoireResult>("/v1/grimoire", body, signal),
};
