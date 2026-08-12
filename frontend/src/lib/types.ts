/** Tipos do domínio, espelham os serializers do backend (docs/api.md). */

export type Role = "admin" | "analyst" | "viewer";

export interface User {
  id: string;
  email: string;
  role: Role;
  is_active: boolean;
}

export interface LoginResponse {
  access: string;
  refresh: string;
  user: User;
}

export type TargetKind = "host" | "domain" | "ip" | "cidr";

export interface Target {
  id: string;
  name: string;
  value: string;
  kind: TargetKind;
  authorized_by: string;
  authorization_scope: string;
  authorization_expires_at: string | null;
  is_active: boolean;
  created_by: string;
  created_at: string;
}

export type ScanType = "discovery" | "fingerprint" | "vulnerability" | "full";
export type ScanStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface Scan {
  id: string;
  created_by: string;
  target_ref: string | null;
  target: string;
  scan_type: ScanType;
  status: ScanStatus;
  authorized_by: string;
  authorization_scope: string;
  started_at: string | null;
  finished_at: string | null;
  failure_reason: string;
  created_at: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Service {
  id: string;
  asset: string;
  port: number;
  protocol: "tcp" | "udp";
  service_name: string;
  product: string | null;
  version: string | null;
  created_at: string;
}

export type TechnologyCategory =
  | "os"
  | "web-server"
  | "framework"
  | "language"
  | "frontend"
  | "cms"
  | "database"
  | "tls"
  | "other";

export type Confidence = "high" | "medium" | "low";

export interface Technology {
  id: string;
  asset: string;
  category: TechnologyCategory;
  name: string;
  version: string | null;
  source: string;
  evidence: string;
  confidence: Confidence;
  created_at: string;
}

export interface Asset {
  id: string;
  ip: string | null;
  hostname: string | null;
  domain: string | null;
  os: string | null;
  status: "active" | "inactive";
  created_at: string;
  services?: Service[];
  technologies?: Technology[];
}

export interface Finding {
  id: string;
  scan: string;
  asset: string;
  vulnerability: string | null;
  category: string;
  title: string;
  severity: Severity;
  cvss: number | null;
  description: string;
  evidence: string;
  recommendation: string;
  created_at: string;
}

export interface Vulnerability {
  id: string;
  cve: string | null;
  title: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  description: string;
  references: string[];
  created_at: string;
}

export interface Paginated<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

// --- Correlation Engine (risk score, priorização, heatmap) ---

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RiskSummary {
  assets: number;
  findings: number;
  severity: SeverityCounts;
  risk_score: number;
  risk_level: Severity;
}

export interface AssetRisk {
  asset: string;
  ip: string | null;
  hostname: string | null;
  domain: string | null;
  risk_score: number;
  risk_level: Severity;
  severity: SeverityCounts;
  findings: number;
}

export interface HeatmapCell {
  category: string;
  severity: Severity;
  count: number;
}

export interface RiskOverview {
  summary: RiskSummary;
  top_assets: AssetRisk[];
  heatmap: HeatmapCell[];
}

// --- Reporting ---

export type ReportType = "executive" | "technical";
export type ReportFormat = "pdf" | "csv" | "json";

export interface Report {
  id: string;
  scan: string;
  report_type: ReportType;
  format: ReportFormat;
  file_path: string;
  created_by: string;
  created_at: string;
}
