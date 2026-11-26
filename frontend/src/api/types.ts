/**
 * The v1 API contract, mirroring backend/necro/schemas.py (and proof_types.py, findings.py,
 * ledger.py). Field names are the JSON names the backend sends.
 */

export type DialectName = "pix" | "asa" | "ios";

export interface ConfigRequest {
  config: string;
  dialect?: DialectName;
}

export interface ProveRequest extends ConfigRequest {
  sample?: string; // a built-in sample name: the engine runs its golden flows (prove and grimoire)
  budget?: number; // examples per context, 1 to 20,000; wins over profile
  seed?: number;
  profile?: "dev" | "ci" | "demo";
  haunt?: boolean; // demo only: prove a deliberately broken candidate (the engine must support it)
}

/** The structured error every failed request returns: `{code, message, line_no?}`. */
export interface ErrorBody {
  code: string;
  message: string;
  line_no?: number;
}

export interface LineIssue {
  line_no: number;
  text: string; // redacted
  reason: string;
  security_relevant: boolean;
  waived: boolean;
}

export interface InterfaceSummary {
  nameif: string;
  hw_name: string;
  security_level: number;
  address: string;
}

export interface AclSummary {
  name: string;
  rules: number;
  classification: string;
}

export interface CoverageSummary {
  total_lines: number;
  counts: Record<string, number>;
  security_relevant: number;
  handled: number;
  waived: number;
  blocking: number;
  ratio: number; // handled / security_relevant
}

export interface ExhumeResult {
  api_version: string;
  dialect: DialectName;
  os_version: string;
  mode: string;
  address_space: string;
  detection_confidence: number;
  input_sha256: string;
  interfaces: InterfaceSummary[];
  acls: AclSummary[];
  bindings: number;
  nat_rules: number;
  coverage: CoverageSummary;
  unparsed: LineIssue[];
}

export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  id: string;
  type: string;
  severity: Severity;
  rule_ref: string;
  related: string[];
  source_line: number;
  zone: string;
  explanation: string;
  recommendation: string;
  label: string;
  verified: boolean;
}

export interface AutopsyResult {
  api_version: string;
  dialect: DialectName;
  findings: Finding[];
  by_severity: Partial<Record<Severity, number>>;
  by_type: Record<string, number>;
}

export type Action = "permit" | "deny";

export interface LedgerEntry {
  id: string;
  class: string;
  reason: string;
  affected: string;
  context: string;
  old_action: Action;
  new_action: Action;
  finding_ref: string;
  approval: "pending" | "accepted" | "rejected";
  approver: string;
  decided_at: string;
  informational: boolean;
}

export type RemediationKind = "remove-rule" | "replace-service" | "narrow-any" | "advise";

/** One remediation offered for one autopsy finding. */
export interface Proposal {
  finding_id: string;
  finding_type: string;
  severity: Severity;
  kind: RemediationKind;
  rule_ref: string;
  summary: string;
  needs_networks: boolean; // narrow-any: the person must confirm the networks
}

export interface Choice {
  finding_id: string;
  kind?: RemediationKind;
  networks?: string[]; // narrow-any only: the networks the person confirms
}

export interface ApprovalDecision {
  approval: "accepted" | "rejected";
  approver: string;
  decided_at: string;
}

export interface TighteningSelection {
  choices: Choice[];
  approvals: Record<string, ApprovalDecision>; // by finding id
}

export interface ResurrectRequest extends ConfigRequest {
  tightening?: TighteningSelection;
  sample?: string;
  budget?: number;
  seed?: number;
  profile?: "dev" | "ci" | "demo";
}

/** The tightened candidate: a separate artifact with its own ledger and proof (governance R1). */
export interface TightenedResult {
  config: string;
  config_lines: number;
  ledger: LedgerEntry[];
  applied: string[];
  skipped: { finding_id: string; reason: string }[];
  notes: string[];
  validation_errors: string[];
  proof: ProofResult | null;
  proof_error: string;
  passed: boolean; // true only when the proof ran and passed
}

export interface ResurrectResult {
  api_version: string;
  dialect: DialectName;
  config: string; // the baseline (like for like) candidate PAN-OS set commands
  config_lines: number;
  ledger: LedgerEntry[];
  unsupported: string[];
  notes: string[];
  blocking: LineIssue[];
  proposals: Proposal[];
  tightened: TightenedResult | null;
}

export interface Flow {
  src: string;
  dst: string;
  proto: number;
  src_port: number;
  dst_port: number;
  icmp_type: number | null;
  established: boolean;
}

export interface Decision {
  action: Action;
  rule_id: string;
  to_zone: string;
  reason: string;
}

export interface Counterexample {
  source: "golden" | "search";
  context: string;
  flow: Flow;
  panos_flow: Flow;
  original: Decision;
  resurrected: Decision;
  original_zone: string;
  expected_action: Action;
  ledger_ids: string[];
  reason: string;
  vector_id: string;
}

export interface SideCoverage {
  rules: number;
  hit: number;
  percent: number;
  unhit: string[];
}

export interface ContextProof {
  context: string;
  implicit: boolean;
  examples: number;
  passed: boolean;
  original: SideCoverage;
  resurrected: SideCoverage;
  ledger_covered: number;
  counterexample: Counterexample | null;
}

export interface ProofResult {
  passed: boolean;
  seed: number;
  budget: number;
  golden: { total: number; passed: number; failures: Counterexample[] };
  contexts: ContextProof[];
  counterexample: Counterexample | null;
}

export interface ProveResult {
  api_version: string;
  dialect: DialectName;
  passed: boolean;
  proof: ProofResult;
  ledger_entries: number;
  blocking_lines: number;
  haunted?: boolean; // present and true only when the engine proved a deliberately broken candidate
}

export type GateId = "G1" | "G2" | "G3" | "G4" | "G5" | "G6";
export type VerdictValue = "GO" | "CONDITIONAL" | "NO-GO";

export interface Check {
  id: string;
  ok: boolean;
  severity: "error" | "warning";
  detail: string;
}

export interface GateResult {
  gate: GateId;
  status: "pass" | "fail" | "waived";
  checks: Check[];
  blocking_reasons: string[];
}

export interface Waiver {
  target: string;
  reason: string;
  approver: string;
  expires_on: string;
}

export interface Verdict {
  value: VerdictValue;
  gates: GateResult[];
  blocking_reasons: string[];
  conditions: string[];
  waivers_used: Waiver[];
  notes: string[];
}

/** The Grimoire: the verdict plus the report as Markdown and print-ready HTML (redacted). */
export interface GrimoireResult {
  api_version: string;
  dialect: DialectName;
  verdict: Verdict;
  coverage: CoverageSummary;
  proof_passed: boolean | null;
  examples_per_context: number;
  seed: number;
  profile: string;
  golden_total: number;
  golden_passed: number;
  markdown: string;
  html: string;
  body_sha256: string;
}
export interface Health {
  status: string;
  version: string;
  commit: string;
}


