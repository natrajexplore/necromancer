/** Low fog over the graveyard. Decorative only; CSS stops the drift under reduced motion. */
export function FogLayer() {
  return (
    <div
      aria-hidden="true"
      data-testid="fog"
      className="pointer-events-none fixed inset-x-0 bottom-0 -z-10 h-72 overflow-hidden"
    >
      <div className="fog-bank absolute -inset-x-1/4 inset-y-0" />
      <div className="fog-bank absolute -inset-x-1/4 inset-y-8 opacity-60 [animation-delay:-19s]" />
    </div>
  );
}
