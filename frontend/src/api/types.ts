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
  budget?: number; // examples per context, 1 to 20,000; wins over profile
  seed?: number;
  profile?: "dev" | "ci" | "demo";
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

export interface ResurrectResult {
  api_version: string;
  dialect: DialectName;
  config: string; // the candidate PAN-OS set commands
  config_lines: number;
  ledger: LedgerEntry[];
  unsupported: string[];
  notes: string[];
  blocking: LineIssue[];
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
}

/**
 * The Grimoire (report + verdict) arrives with the migration-governance spec. Until then the
 * backend answers 501 `not-implemented`, which the client raises as an ApiError.
 */
export interface GrimoireResult {
  api_version: string;
  [field: string]: unknown;
}

export interface Health {
  status: string;
  version: string;
  commit: string;
}
