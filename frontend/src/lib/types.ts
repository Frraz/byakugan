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
  scans_count: number;
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

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// --- Motor ofensivo: perfis/opções de scan (Fase 0-4 do plano ofensivo) ---

export type Intensity = "safe" | "normal" | "aggressive";
export type PortSet = "top16" | "top100" | "top1000";

export interface ScanOptions {
  intensity: Intensity;
  port_set: PortSet;
  wordlist_size: number;
  max_hosts: number;
  max_pages: number;
  max_workers: number;
  rate_delay: number;
  /** `null` = todos os checks do scan_type habilitados (padrão). */
  enabled_checks: string[] | null;
}

export interface Scan {
  id: string;
  created_by: string;
  target_ref: string | null;
  target: string;
  target_name: string | null;
  scan_type: ScanType;
  status: ScanStatus;
  authorized_by: string;
  authorization_scope: string;
  started_at: string | null;
  finished_at: string | null;
  failure_reason: string;
  options: ScanOptions;
  progress: number;
  phase: string;
  findings_count: number;
  severity_counts: SeverityCounts;
  created_at: string;
}

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
  findings_count: number;
  created_at: string;
  services?: Service[];
  technologies?: Technology[];
}

export interface Vulnerability {
  id: string;
  cve: string | null;
  title: string;
  severity: Severity;
  cvss_score: number | string | null;
  cvss_vector: string | null;
  description: string;
  references: string[];
  created_at: string;
}

/** Resumo de ativo aninhado num finding (backend AssetSummarySerializer). */
export interface AssetSummary {
  id: string;
  hostname: string | null;
  ip: string | null;
  domain: string | null;
}

/** Resumo de scan aninhado num finding (backend ScanSummarySerializer). */
export interface ScanSummary {
  id: string;
  target: string;
  scan_type: ScanType;
  created_at: string;
}

/** Categorias de finding produzidas pelo motor ofensivo (backend FindingCategory). */
export type FindingCategory =
  | "software"
  | "service"
  | "network"
  | "credential"
  | "tls"
  | "certificate"
  | "dns"
  | "email-security"
  | "subdomain"
  | "web-headers"
  | "cookie"
  | "cors"
  | "exposure"
  | "http-method"
  | "injection";

// --- Correlação & triagem (Fase 5) ---

export type TriageStatus = "open" | "fixed" | "false-positive" | "accepted-risk";

export interface FindingTriage {
  id: string;
  dedup_key: string;
  asset: string;
  status: TriageStatus;
  note: string;
  updated_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  scan: ScanSummary | null;
  asset: AssetSummary | null;
  vulnerability: Vulnerability | null;
  category: FindingCategory;
  title: string;
  severity: Severity;
  cvss: number | null;
  description: string;
  evidence: string;
  recommendation: string;
  dedup_key: string;
  triage_status: TriageStatus;
  created_at: string;
}

export interface Paginated<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

// --- Correlation Engine (risk score, priorização, heatmap) ---

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
  category_label: string;
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
  scan_target: string | null;
  scan_type: ScanType | null;
  scan_finished_at: string | null;
  report_type: ReportType;
  format: ReportFormat;
  file_path: string;
  file_size: number | null;
  created_by: string;
  created_at: string;
}

// --- Knowledge Base ---

export interface KnowledgeArticle {
  id: string;
  slug: string;
  title: string;
  category: string;
  summary: string;
  impact: string;
  remediation_steps: string[];
  references: string[];
  created_at: string;
  updated_at: string;
}
