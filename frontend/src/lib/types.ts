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
  /** Nº de findings com módulo de exploração automatizado (o que "Explorar" pode provar). */
  exploitable_findings_count: number;
  created_at: string;
}

export type OwaspEdition = "2021" | "2025";

/** Status derivado de uma célula da matriz (backend `owasp_coverage._cell_status`). */
export type OwaspCellStatus = "proven" | "found" | "tested" | "limited" | "not-tested";

/** Uma linha (categoria OWASP) da matriz de cobertura de uma edição. */
export interface OwaspCoverageRow {
  code: string;
  label: string;
  tested: boolean;
  limited_coverage: boolean;
  findings: number;
  highest_severity: Severity | null;
  proven: boolean;
  status: OwaspCellStatus;
}

export interface OwaspEditionSummary {
  tested: number;
  found: number;
  proven: number;
  limited: number;
  total: number;
}

/** Matriz de cobertura OWASP (2021 + 2025) de um scan — `GET /scans/{id}/owasp-coverage/`. */
export interface OwaspCoverage {
  "2021": OwaspCoverageRow[];
  "2025": OwaspCoverageRow[];
  summary: Record<OwaspEdition, OwaspEditionSummary>;
}

/** Resumo agregado da aba de Scans (KPIs) — backend `GET /scans/stats/`. */
export interface ScanStats {
  total: number;
  active: number;
  by_status: Record<ScanStatus, number>;
  findings_total: number;
  findings_by_severity: SeverityCounts;
  exploits_proven: number;
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
  | "waf"
  | "cdn"
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

export type DnsRecordType = "MX" | "NS" | "TXT" | "SOA" | "SRV" | "CNAME" | "CAA" | "PTR";

/** Registro DNS não-A/AAAA descoberto de um domínio (A/AAAA viram o próprio Asset). */
export interface DnsRecord {
  id: string;
  asset: string;
  domain: string;
  record_type: DnsRecordType;
  value: string;
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
  dns_records?: DnsRecord[];
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
  | "injection"
  | "access-control"
  | "auth"
  | "integrity";

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
  /** Classe de vulnerabilidade que liga o finding ao playbook/evidência. */
  playbook_key: string;
  /** Classificação OWASP Top 10 (2021/2025) — "" se a classe não tiver mapeamento. */
  owasp_2021: string;
  owasp_2025: string;
  /** CWE primário (ex.: "CWE-89") — "" se não mapeado. */
  cwe: string;
  /** Técnica MITRE ATT&CK primária (ex.: "T1190") — "" se não mapeada (honestidade, não lacuna escondida). */
  mitre_technique: string;
  triage_status: TriageStatus;
  created_at: string;
}

/** Uma ocorrência de uma vulnerabilidade agrupada (num alvo/ativo específico). */
export interface GroupOccurrence {
  id: string;
  severity: Severity;
  cvss: number | null;
  triage_status: TriageStatus;
  created_at: string;
  asset: AssetSummary | null;
  scan: ScanSummary | null;
}

/** Vulnerabilidade lógica consolidada entre alvos (`GET /findings/grouped/`). */
export interface GroupedFinding {
  group_key: string;
  category: FindingCategory;
  title: string;
  severity: Severity;
  cvss: number | null;
  /** Nº de alvos/ativos distintos afetados. */
  targets: number;
  /** Total de ocorrências (todas as execuções). */
  occurrences: number;
  open_count: number;
  triage_status: "open" | "resolved";
  last_seen: string;
  finding_id: string | null;
  playbook_key: string;
  owasp_2021: string;
  owasp_2025: string;
  cwe: string;
  mitre_technique: string;
  description: string;
  evidence: string;
  recommendation: string;
  cve: string | null;
  affected: GroupOccurrence[];
}

// --- Motor de exploração & Evidências (Fase 7+) ---

export type EvidenceStatus =
  | "proven"
  | "attempted"
  | "failed"
  | "blocked"
  | "not-attempted";

export type ImpactLevel =
  | "rce"
  | "db-read"
  | "file-read"
  | "auth-bypass"
  | "ssrf"
  | "info-disclosure"
  | "session"
  | "none";

/** Um passo que o motor de exploração de fato executou (o "até onde foi"). */
export interface EvidenceStep {
  action: string;
  request?: string;
  response_excerpt?: string;
  result?: string;
}

/** Finding adjacente encadeado numa exploração. */
export interface EvidenceChainLink {
  finding: string;
  impact: string;
  description: string;
}

/** Resumo de finding aninhado numa evidência. */
export interface FindingRef {
  id: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  playbook_key: string;
}

/** Resultado imutável de uma exploração automatizada (aba Evidências). */
export interface Evidence {
  id: string;
  finding: FindingRef | null;
  scan: string;
  asset: AssetSummary | null;
  playbook_key: string;
  status: EvidenceStatus;
  impact_level: ImpactLevel;
  proof: string;
  steps_performed: EvidenceStep[];
  chain: EvidenceChainLink[];
  roe_profile: string;
  created_at: string;
}

/** Passo manual de PoC de um playbook curado. */
export interface PlaybookStep {
  action: string;
  command?: string;
  expected?: string;
}

/** Estágio de escalação ("até onde dá para ir") de um playbook. */
export interface EscalationStage {
  stage: string;
  impact: ImpactLevel | string;
  description: string;
}

/** Guia curado de exploração por classe de vulnerabilidade (aba Evidências). */
export interface ExploitationPlaybook {
  id: string;
  key: string;
  title: string;
  category: FindingCategory;
  vuln_class: string;
  summary: string;
  prerequisites: string;
  steps: PlaybookStep[];
  escalation_path: EscalationStage[];
  max_impact: ImpactLevel;
  tools: string[];
  references: string[];
  /** Regra de detecção Sigma (YAML) para o time de defesa — "" quando a
   * classe não tem assinatura de log confiável (ver docs/exploitation-engine.md). */
  detection_rule: string;
  created_at: string;
  updated_at: string;
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

/** Combinação de classes que, juntas no mesmo ativo, formam um risco mais
 * grave que a soma das partes (ex.: XSS + CSP fraca) — correlação purple
 * team (ver docs/exploitation-engine.md). */
export interface FindingChain {
  asset: string;
  ip: string | null;
  hostname: string | null;
  domain: string | null;
  chain_key: string;
  title: string;
  description: string;
  severity: Severity;
  classes: string[];
}

export interface RiskOverview {
  summary: RiskSummary;
  top_assets: AssetRisk[];
  heatmap: HeatmapCell[];
  chains: FindingChain[];
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

// --- Auditoria ---

export type AuditSeverity = "info" | "warning" | "critical";

/** Evento imutável da trilha de auditoria (admin-only) — `GET /audit-logs/`. */
export interface AuditLogEntry {
  id: string;
  /** FK cru do usuário (id) — preferir `user_email` para exibição. */
  user: string | null;
  user_email: string | null;
  action: string;
  severity: AuditSeverity;
  source: string | null;
  metadata: Record<string, unknown>;
  timestamp: string;
}
