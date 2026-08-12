/** Hooks React Query para Targets, Scans, Assets e Findings. */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, downloadFile } from "../lib/api";
import type {
  Asset,
  Finding,
  Paginated,
  Report,
  ReportFormat,
  ReportType,
  RiskOverview,
  Scan,
  Service,
  Target,
  Technology,
  Vulnerability,
} from "../lib/types";

// --- Targets ---

export function useTargets(search?: string) {
  return useQuery({
    queryKey: ["targets", search],
    queryFn: () => apiFetch<Paginated<Target>>("/targets/", { params: { search } }),
  });
}

export interface CreateTargetInput {
  name: string;
  value: string;
  authorized_by: string;
  authorization_scope: string;
}

export function useCreateTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateTargetInput) =>
      apiFetch<Target>("/targets/", { method: "POST", body: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
  });
}

// --- Scans ---

export function useScans(params?: { status?: string; scan_type?: string }) {
  return useQuery({
    queryKey: ["scans", params],
    queryFn: () => apiFetch<Paginated<Scan>>("/scans/", { params }),
    refetchInterval: 5000, // polling do status
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

export interface CreateScanInput {
  scan_type: string;
  target_ref?: string;
  target?: string;
  authorized_by?: string;
  authorization_scope?: string;
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
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

// --- Assets ---

export function useAssets(search?: string) {
  return useQuery({
    queryKey: ["assets", search],
    queryFn: () => apiFetch<Paginated<Asset>>("/assets/", { params: { search } }),
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

// --- Vulnerabilities & Findings ---

export function useVulnerabilities(params?: { severity?: string; search?: string }) {
  return useQuery({
    queryKey: ["vulnerabilities", params],
    queryFn: () => apiFetch<Paginated<Vulnerability>>("/vulnerabilities/", { params }),
  });
}

export function useFindings(params?: { severity?: string; asset?: string; scan?: string }) {
  return useQuery({
    queryKey: ["findings", params],
    queryFn: () => apiFetch<Paginated<Finding>>("/findings/", { params }),
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

export function useReports(params?: { scan?: string; report_type?: string; format?: string }) {
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
