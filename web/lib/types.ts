export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "running" | "completed" | "failed";

export interface ComplianceMapping {
  id: number;
  compliance_type: string;
  compliance_id: string;
  compliance_title: string | null;
  compliance_category: string | null;
  notes: string | null;
}

export interface Vulnerability {
  id: number;
  scan_id: string;
  rule_id: string | null;
  title: string;
  description: string | null;
  severity: SeverityLevel;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  code_snippet: string | null;
  analysis_type: string;
  is_false_positive: boolean;
  confidence: number;
  attack_scenario: string | null;
  remediation: string | null;
  remediation_code: string | null;
  created_at: string;
  compliance_mappings: ComplianceMapping[];
}

export interface Scan {
  id: string;
  target_path: string;
  started_at: string;
  completed_at: string | null;
  status: ScanStatus;
  analysis_type: string;
  model_used: string | null;
  compliance_types: string[] | null;
  total_files: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface ScanDetail extends Scan {
  error_message: string | null;
}

export interface ScanListResponse {
  items: Scan[];
  total: number;
}

export interface SeverityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Stats {
  total_scans: number;
  total_vulnerabilities: number;
  severity_distribution: SeverityStats;
  recent_scans: Scan[];
}
