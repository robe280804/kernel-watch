// TypeScript mirrors of the KernelWatch API response shapes. Keep these in sync
// with the Go source of truth:
//   Alert        -> internal/alerter/alerter.go (Alert struct)
//   StatsResult  -> internal/storage/query.go   (StatsResult, Count)
//   Suppression  -> internal/suppress/suppress.go (Rule)

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Scope = 'host' | 'container';

export interface Alert {
  id: string;
  rule_id?: string;
  server_name: string;
  timestamp: string; // RFC3339
  severity: Severity;
  scope?: string; // "" treated as container by the daemon
  container_id?: string;
  container_name?: string;
  image_name?: string;
  syscall?: string;
  pid: number;
  process_name: string;
  reason: string;
  details?: Record<string, unknown>;
  parent_name?: string;
  ancestry?: string[];
  cmdline?: string;
  mitre_ttp?: string;
  mitre_tactic?: string;
  tags?: string[];
  kill_chain_phase?: string;
  risk_score?: number;
}

export interface AlertsResponse {
  count: number;
  alerts: Alert[];
}

export interface Count {
  key: string;
  count: number;
}

export interface StatsResult {
  since: string;
  total: number;
  by_severity: Count[] | null;
  by_scope: Count[] | null;
  by_rule: Count[] | null;
  top_containers: Count[] | null;
}

export interface SuppressionRule {
  id?: string;
  rule_id?: string;
  scope?: string;
  hostname?: string;
  container_name?: string;
  process_name?: string;
  substr?: string;
  reason?: string;
  created_by?: string;
  created_at?: string;
}

export interface SuppressionsResponse {
  count: number;
  suppressions: SuppressionRule[];
}

// The body the add-suppression form sends. Only the fields the server accepts
// (server-controlled id/created_at are ignored on input).
export interface NewSuppression {
  rule_id?: string;
  scope?: string;
  hostname?: string;
  container_name?: string;
  process_name?: string;
  substr?: string;
  reason?: string;
}
