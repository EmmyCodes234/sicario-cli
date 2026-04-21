/**
 * Shared TypeScript types for the Sicario Cloud Dashboard.
 * Data is fetched directly from Convex via React hooks — no REST API needed.
 */

export type Severity = "Info" | "Low" | "Medium" | "High" | "Critical";
export type TriageState = "Open" | "Reviewing" | "ToFix" | "Fixed" | "Ignored" | "AutoIgnored";

export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  rule_name: string;
  file_path: string;
  line: number;
  column: number;
  end_line: number | null;
  end_column: number | null;
  snippet: string;
  severity: Severity;
  confidence_score: number;
  reachable: boolean;
  cloud_exposed: boolean | null;
  cwe_id: string | null;
  owasp_category: string | null;
  fingerprint: string;
  triage_state: TriageState;
  triage_note: string | null;
  assigned_to: string | null;
  created_at: string;
  updated_at: string;
}

export interface Paginated<T> {
  page: number;
  per_page: number;
  total: number;
  items: T[];
}

export interface AnalyticsOverview {
  total_findings: number;
  open_findings: number;
  fixed_findings: number;
  ignored_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  total_scans: number;
  avg_scan_duration_ms: number;
}

export interface TrendDataPoint {
  timestamp: string;
  open_findings: number;
  new_findings: number;
  fixed_findings: number;
}

export interface MttrMetrics {
  overall_mttr_hours: number;
  by_severity: Record<string, number>;
}

export interface Scan {
  id: string;
  repository: string;
  branch: string;
  commit_sha: string;
  timestamp: string;
  duration_ms: number;
  rules_loaded: number;
  files_scanned: number;
  language_breakdown: Record<string, number>;
  tags: string[];
  findings_count?: number;
  critical_count?: number;
  high_count?: number;
}

export interface Project {
  id: string;
  name: string;
  repository_url: string;
  description: string;
  team_id: string | null;
  created_at: string;
}

// ── RBAC Types ────────────────────────────────────────────────────────────────

export type Role = "admin" | "manager" | "developer";

export interface Membership {
  user_id: string;
  org_id: string;
  role: Role;
  team_ids: string[];
  created_at: string;
}

export type SsoProvider = "saml" | "oidc";

export interface SsoConfig {
  org_id: string;
  provider: SsoProvider;
  issuer_url: string;
  client_id: string;
  metadata_url: string | null;
  enabled: boolean;
  created_at: string;
}
