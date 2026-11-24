import { ApiError } from "../api/client";

/** A failed request in plain language: what happened, the error code, and the line if any. */
export function ErrorNotice({ error, what = "exhumed" }: { error: unknown; what?: string }) {
  const apiError = error instanceof ApiError ? error : null;
  const message = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div role="alert" className="rounded-md border border-blood/60 bg-crypt px-4 py-3 text-bone">
      <p className="font-semibold text-blood">The config could not be {what}.</p>
      <p className="mt-1">{message}</p>
      {apiError && (
        <p className="mt-1 text-sm text-ash">
          Error code <code className="font-mono">{apiError.code}</code>
          {apiError.lineNo !== undefined && <> at line {apiError.lineNo}</>}
          {apiError.retryAfter !== undefined && <>. Try again in {apiError.retryAfter} s</>}.
        </p>
      )}
    </div>
  );
}
