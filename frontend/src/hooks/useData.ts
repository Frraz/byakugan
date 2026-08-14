/** Hooks React Query para Targets, Scans, Assets, Findings, Reports e KB. */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, downloadFile } from "../lib/api";
import type {
  Asset,
  Evidence,
  ExploitationPlaybook,
  Finding,
  FindingTriage,
  KnowledgeArticle,
  Paginated,
  Report,
  ReportFormat,
  ReportType,
  RiskOverview,
  Scan,
  ScanOptions,
  Service,
  Target,
  Technology,
  TriageStatus,
  Vulnerability,
} from "../lib/types";

/** Há algum scan ativo (pending/running) na página atual? Controla o polling. */
function hasActiveScan(page?: Paginated<Scan>): boolean {
  return Boolean(page?.results.some((s) => s.status === "pending" || s.status === "running"));
}

// --- Targets ---

export type TargetFilters = {
  search?: string;
  kind?: string;
  is_active?: string;
  page?: number;
}

export function useTargets(params?: TargetFilters) {
  return useQuery({
    queryKey: ["targets", params],
    queryFn: () => apiFetch<Paginated<Target>>("/targets/", { params }),
  });
}

export interface TargetInput {
  name: string;
  value: string;
  authorized_by: string;
  authorization_scope: string;
  authorization_expires_at?: string | null;
  is_active?: boolean;
}

export function useCreateTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: TargetInput) =>
      apiFetch<Target>("/targets/", { method: "POST", body: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
  });
}

export function useUpdateTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: Partial<TargetInput> }) =>
      apiFetch<Target>(`/targets/${id}/`, { method: "PATCH", body: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
  });
}

export function useDeleteTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<void>(`/targets/${id}/`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
  });
}

// --- Scans ---

export type ScanFilters = {
  status?: string;
  scan_type?: string;
  search?: string;
  page?: number;
}

export function useScans(params?: ScanFilters) {
  return useQuery({
    queryKey: ["scans", params],
    queryFn: () => apiFetch<Paginated<Scan>>("/scans/", { params }),
    // Polling adaptativo: só refetch enquanto houver scan ativo (evita 429).
    refetchInterval: (query) => (hasActiveScan(query.state.data) ? 4000 : false),
  });
}

export function useScan(id: string) {
  return useQuery({
    queryKey: ["scan", id],
    queryFn: () => apiFetch<Scan>(`/scans/${id}/`),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "pending" || status === "running" ? 3000 : false;
    },
  });
}

export function useScanFindings(id: string) {
  return useQuery({
    queryKey: ["scan", id, "findings"],
    queryFn: () => apiFetch<Finding[]>(`/scans/${id}/findings/`),
  });
}

export function useScanServices(id: string) {
  return useQuery({
    queryKey: ["scan", id, "services"],
    queryFn: () => apiFetch<Service[]>(`/scans/${id}/services/`),
  });
}

export interface CreateScanInput {
  scan_type: string;
  target_ref?: string;
  target?: string;
  authorized_by?: string;
  authorization_scope?: string;
  options?: Partial<ScanOptions>;
}

export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateScanInput) =>
      apiFetch<Scan>("/scans/", { method: "POST", body: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<Scan>(`/scans/${id}/cancel/`, { method: "POST" }),
    onSuccess: (_data, id) => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scan", id] });
    },
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<void>(`/scans/${id}/`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["reports"] });
    },
  });
}

// --- Assets ---

export function useAssets(params?: { search?: string; status?: string; page?: number }) {
  return useQuery({
    queryKey: ["assets", params],
    queryFn: () => apiFetch<Paginated<Asset>>("/assets/", { params }),
  });
}

export function useAsset(id: string) {
  return useQuery({
    queryKey: ["asset", id],
    queryFn: () => apiFetch<Asset>(`/assets/${id}/`),
  });
}

export function useAssetServices(id: string) {
  return useQuery({
    queryKey: ["asset", id, "services"],
    queryFn: () => apiFetch<Service[]>(`/assets/${id}/services/`),
  });
}

export function useAssetTechnologies(id: string) {
  return useQuery({
    queryKey: ["asset", id, "technologies"],
    queryFn: () => apiFetch<Technology[]>(`/assets/${id}/technologies/`),
  });
}

export function useDeleteAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<void>(`/assets/${id}/`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["risk-overview"] });
    },
  });
}

// --- Vulnerabilities & Findings ---

export function useVulnerabilities(params?: { severity?: string; search?: string; page?: number }) {
  return useQuery({
    queryKey: ["vulnerabilities", params],
    queryFn: () => apiFetch<Paginated<Vulnerability>>("/vulnerabilities/", { params }),
  });
}

export type FindingFilters = {
  severity?: string;
  category?: string;
  asset?: string;
  scan?: string;
  search?: string;
  page?: number;
}

export function useFindings(params?: FindingFilters) {
  return useQuery({
    queryKey: ["findings", params],
    queryFn: () => apiFetch<Paginated<Finding>>("/findings/", { params }),
  });
}

export interface TriageFindingInput {
  id: string;
  status: TriageStatus;
  note?: string;
}

/** Classifica o achado lógico (por dedup_key) — aberto/corrigido/falso-positivo/risco aceito. */
export function useTriageFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, note }: TriageFindingInput) =>
      apiFetch<FindingTriage>(`/findings/${id}/triage/`, {
        method: "POST",
        body: { status, note },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["scan"] });
      qc.invalidateQueries({ queryKey: ["risk-overview"] });
    },
  });
}

// --- Motor de exploração & Evidências ---

export type EvidenceFilters = {
  status?: string;
  impact_level?: string;
  scan?: string;
  asset?: string;
  finding?: string;
  playbook_key?: string;
  search?: string;
  page?: number;
};

export function useEvidence(params?: EvidenceFilters) {
  return useQuery({
    queryKey: ["evidence", params],
    queryFn: () => apiFetch<Paginated<Evidence>>("/evidence/", { params }),
  });
}

export function usePlaybooks(params?: { category?: string; search?: string; page?: number }) {
  return useQuery({
    queryKey: ["playbooks", params],
    queryFn: () => apiFetch<Paginated<ExploitationPlaybook>>("/playbooks/", { params }),
  });
}

/** Um playbook por chave (ex.: `injection.sqli-error`); `null` desativa a query. */
export function usePlaybook(key: string | null | undefined) {
  return useQuery({
    queryKey: ["playbook", key],
    queryFn: () => apiFetch<ExploitationPlaybook>(`/playbooks/${key}/`),
    enabled: Boolean(key),
  });
}

/** Dispara a fase de exploração (prova de impacto) sobre um scan concluído. */
export function useTriggerExploit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) =>
      apiFetch<{ detail: string; task_id: string | null }>(`/scans/${scanId}/exploit/`, {
        method: "POST",
      }),
    onSuccess: (_data, scanId) => {
      qc.invalidateQueries({ queryKey: ["evidence"] });
      qc.invalidateQueries({ queryKey: ["scan", scanId] });
    },
  });
}

// --- Correlation Engine ---

export function useRiskOverview(limit = 5) {
  return useQuery({
    queryKey: ["risk-overview", limit],
    queryFn: () => apiFetch<RiskOverview>("/risk/overview/", { params: { limit } }),
  });
}

// --- Reports ---

export function useReports(params?: {
  scan?: string;
  report_type?: string;
  format?: string;
  page?: number;
}) {
  return useQuery({
    queryKey: ["reports", params],
    queryFn: () => apiFetch<Paginated<Report>>("/reports/", { params }),
  });
}

export interface CreateReportInput {
  scan: string;
  report_type: ReportType;
  format: ReportFormat;
}

export function useCreateReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateReportInput) =>
      apiFetch<Report>("/reports/", { method: "POST", body: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });
}

export function useDeleteReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<void>(`/reports/${id}/`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });
}

export function useDownloadReport() {
  return useMutation({
    mutationFn: ({ id, filename }: { id: string; filename: string }) =>
      downloadFile(`/reports/${id}/download/`, filename),
  });
}

// --- Knowledge Base ---

export function useKnowledgeArticles(params?: {
  category?: string;
  search?: string;
  page?: number;
}) {
  return useQuery({
    queryKey: ["knowledge-base", params],
    queryFn: () => apiFetch<Paginated<KnowledgeArticle>>("/knowledge-base/", { params }),
  });
}

export interface CreateKnowledgeArticleInput {
  slug: string;
  title: string;
  category: string;
  summary: string;
  impact: string;
  remediation_steps: string[];
  references: string[];
}

export function useCreateKnowledgeArticle() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateKnowledgeArticleInput) =>
      apiFetch<KnowledgeArticle>("/knowledge-base/", { method: "POST", body: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["knowledge-base"] }),
  });
}

export function useDeleteKnowledgeArticle() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<void>(`/knowledge-base/${id}/`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["knowledge-base"] }),
  });
}
