import type { Counterexample, Decision, Flow } from "../api/types";
import { Hint } from "./Hint";

const PROTOCOLS: Record<number, string> = {
  1: "icmp",
  6: "tcp",
  17: "udp",
  47: "gre",
  50: "esp",
  51: "ah",
  88: "eigrp",
  89: "ospf",
};

export function protocolName(proto: number): string {
  return PROTOCOLS[proto] ?? `ip protocol ${proto}`;
}

/** The 5-tuple in one line, e.g. `tcp 198.51.100.7:40000 -> 10.1.0.5:443`. */
export function describeFlow(flow: Flow): string {
  const name = protocolName(flow.proto);
  const state = flow.established ? " (established)" : "";
  if (flow.proto === 6 || flow.proto === 17) {
    return `${name} ${flow.src}:${flow.src_port} -> ${flow.dst}:${flow.dst_port}${state}`;
  }
  if (flow.proto === 1) {
    return `icmp ${flow.src} -> ${flow.dst}${flow.icmp_type === null ? "" : ` type ${flow.icmp_type}`}`;
  }
  return `${name} ${flow.src} -> ${flow.dst}`;
}

function Side({ title, decision }: { title: string; decision: Decision }) {
  const permitted = decision.action === "permit";
  return (
    <div className="rounded-md border border-stone bg-void px-3 py-2">
      <h4 className="text-sm text-ash">{title}</h4>
      <p className={permitted ? "text-spectral" : "text-blood"}>{permitted ? "Permitted" : "Denied"}</p>
      <p className="text-sm text-bone">
        Matching rule: <code className="font-mono">{decision.rule_id}</code>
      </p>
      <p className="text-sm text-bone">
        To zone: <code className="font-mono">{decision.to_zone}</code>
      </p>
      <p className="text-sm text-ash">{decision.reason}</p>
    </div>
  );
}

/** The packet that refused to rest: the smallest flow on which the two configs disagree. */
export function CounterexampleCard({ example }: { example: Counterexample }) {
  const sameFlow = describeFlow(example.flow) === describeFlow(example.panos_flow);
  return (
    <article
      aria-labelledby="counterexample-title"
      className="rounded-lg border border-blood bg-crypt p-5"
    >
      <h3 id="counterexample-title" className="font-display text-2xl text-bone">
        <Hint explain="Counterexample: the smallest generated or hand-written packet on which the original config and the PAN-OS candidate give different answers.">
          The packet that refused to rest
        </Hint>
      </h3>
      <p className="mt-2 text-bone">
        <code className="font-mono">{describeFlow(example.flow)}</code>
      </p>
      {!sameFlow && (
        <p className="text-sm text-ash">
          Checked on PAN-OS as <code className="font-mono">{describeFlow(example.panos_flow)}</code>{" "}
          (addresses translated to the pre-NAT form).
        </p>
      )}
      <p className="mt-1 text-sm text-ash">
        Context <code className="font-mono">{example.context}</code>. Found by{" "}
        {example.source === "golden"
          ? `a hand-verified golden flow (${example.vector_id})`
          : "the generated search"}
        .
      </p>
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Side title="Original config says" decision={example.original} />
        <Side title="Resurrected config says" decision={example.resurrected} />
      </div>
      <p className="mt-3 text-bone">{example.reason}</p>
      {example.ledger_ids.length > 0 && (
        <p className="mt-1 text-sm text-ash">Ledger entries involved: {example.ledger_ids.join(", ")}</p>
      )}
    </article>
  );
}
