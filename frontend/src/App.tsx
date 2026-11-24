import { useHealth } from "./api/hooks";
import { FogLayer } from "./components/FogLayer";
import { Graveyard } from "./screens/Graveyard";

/** Which engine answered: version and commit from /healthz, or how to start it. */
function EngineStatus() {
  const health = useHealth();
  if (health.isSuccess) {
    return (
      <p>
        Engine {health.data.version} (commit <code className="font-mono">{health.data.commit}</code>)
      </p>
    );
  }
  if (health.isError) {
    return (
      <p className="text-candle">
        The engine is not reachable. Start it with{" "}
        <code className="font-mono">uv run python -m uvicorn api.main:app --port 8000</code> in
        backend/.
      </p>
    );
  }
  return <p>Contacting the engine…</p>;
}

export function App() {
  return (
    <div className="relative min-h-screen">
      <FogLayer />
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-spectral focus:px-3 focus:py-2 focus:text-void"
      >
        Skip to the graveyard
      </a>
      <header className="mx-auto max-w-7xl px-6 pt-10">
        <h1 className="font-display text-5xl tracking-wide text-bone">
          NECROMANCER<span className="candle text-candle" aria-hidden="true">.</span>
        </h1>
        <p className="mt-2 text-lg text-ash">
          Raise dead firewall configs as zero-trust policy, and prove they came back the same.
        </p>
      </header>
      <main id="main" className="mx-auto max-w-7xl px-6 py-10">
        <Graveyard />
      </main>
      <footer className="mx-auto max-w-7xl px-6 pb-10 text-sm text-ash">
        <EngineStatus />
        <p className="mt-1">
          Output is a candidate configuration for people to review. NECROMANCER never connects to a
          device.
        </p>
      </footer>
    </div>
  );
}
