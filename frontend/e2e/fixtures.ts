/** Somente testes: dados de laboratório, nunca importados pela aplicação. */
import type { Page } from "@playwright/test";

const date = "2026-10-11T10:00:00Z";
export const severity = { critical: 1, high: 2, medium: 3, low: 4, info: 1 };
export const target = { id: "target-1", name: "Laboratório autorizado", value: "laboratorio.example.test", kind: "domain", authorization_scope: "laboratorio.example.test", authorized_by: "lab@example.test", authorization_expires_at: "2027-12-31T10:00:00Z", is_active: true, scans_count: 1, created_by: "user-1", created_at: date };
export const scan = { id: "scan-1", created_by: "user-1", target_ref: target.id, target: target.value, target_name: target.name, scan_type: "full", status: "completed", authorized_by: "lab@example.test", authorization_scope: target.value, started_at: date, finished_at: date, failure_reason: "", options: { intensity: "normal", port_set: "top100", wordlist_size: 100, max_hosts: 256, max_pages: 20, max_workers: 4, rate_delay: 0, enabled_checks: null }, progress: 100, phase: "Concluído", findings_count: 1, severity_counts: severity, exploitable_findings_count: 0, created_at: date };
export const asset = { id: "asset-1", hostname: target.value, domain: target.value, ip: "2001:db8:85a3::8a2e:370:7334", os: "Linux", status: "active", findings_count: 1, created_at: date, services: [{ id: "service-1", asset: "asset-1", port: 443, protocol: "tcp", service_name: "https", product: "nginx", version: "1.26", created_at: date }], technologies: [{ id: "tech-1", asset: "asset-1", category: "web-server", name: "nginx", version: "1.26", source: "HTTP", evidence: "Server: nginx", confidence: "high", created_at: date }], dns_records: [{ id: "dns-1", asset: "asset-1", record_type: "TXT", domain: target.value, value: "v=spf1 " + "include:email.example.test ".repeat(20) + "-all", created_at: date }] };
export const finding = { id: "finding-1", scan, asset, vulnerability: null, category: "web-headers", title: "Header de segurança ausente", severity: "medium", cvss: 5.3, description: "Revisar a política de segurança da aplicação.", evidence: "URL: https://laboratorio.example.test/ | Header não observado", recommendation: "Definir uma política adequada ao contexto.", dedup_key: "key-1", playbook_key: "", owasp_2021: "A05", owasp_2025: "A02", cwe: "CWE-693", mitre_technique: "", triage_status: "open", created_at: date };
export const group = { ...finding, group_key: "group-1", finding_id: finding.id, targets: 1, occurrences: 1, open_count: 1, last_seen: date, cve: null, affected: [{ ...finding, id: finding.id }] };
export const report = { id: "report-1", scan: scan.id, scan_target: target.value, scan_type: "full", scan_finished_at: date, report_type: "technical", format: "json", file_path: "", file_size: 1500, created_by: "user-1", created_at: date };
export const article = { id: "article-1", slug: "headers", title: "Headers de segurança", category: "web-headers", summary: "Revisão de políticas HTTP.", impact: "Defesa em profundidade.", remediation_steps: ["Revise o contexto da aplicação.", "Valide a configuração."], references: ["https://example.test/reference"], created_at: date, updated_at: date };
const evidence = { id: "evidence-1", finding, scan: scan.id, asset, playbook_key: "headers", status: "blocked", impact_level: "none", proof: "Motor de exploração desabilitado no laboratório.", steps_performed: [{ action: "Verificar autorização", result: "Bloqueado pelo controle operacional" }], chain: [], roe_profile: "non-destructive", created_at: date };
const row = { code: "A05", label: "A05:2021 - Security Misconfiguration", tested: true, limited_coverage: false, findings: 1, highest_severity: "medium", proven: false, status: "found" };
const coverage = { "2021": [row, { ...row, code: "A04", label: "A04:2021 - Insecure Design", tested: false, limited_coverage: true, findings: 0, highest_severity: null, status: "limited" }], "2025": [{ ...row, code: "A02", label: "A02:2025 - Security Misconfiguration" }], summary: { "2021": { tested: 1, found: 1, proven: 0, limited: 1, total: 10 }, "2025": { tested: 1, found: 1, proven: 0, limited: 0, total: 10 } } };
export const paginated = (results: unknown[], count = results.length) => ({ count, results, next: null, previous: null });

export async function laboratory(page: Page, options: { role?: "admin" | "analyst" | "viewer"; theme?: "dark" | "light"; state?: "data" | "empty" | "error" } = {}) {
  const { role = "admin", theme = "dark", state = "data" } = options;
  const user = { id: "user-1", email: "lab@example.test", role, is_active: true };
  await page.addInitScript(({ user, theme }) => {
    localStorage.setItem("byakugan-auth", JSON.stringify({ state: { user, access: "laboratory-token", refresh: "laboratory-refresh" }, version: 0 }));
    localStorage.setItem("byakugan-theme", JSON.stringify({ state: { theme }, version: 0 }));
  }, { user, theme });
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api/, "");
    if (state === "error" && !path.startsWith("/auth/")) return route.fulfill({ status: 503, json: { detail: "Serviço indisponível no cenário de teste." } });
    const list = (values: unknown[]) => paginated(state === "empty" ? [] : values);
    if (route.request().method() === "POST") {
      if (path === "/reports/") return route.fulfill({ status: 201, json: { ...report, ...route.request().postDataJSON() } });
      if (path === "/targets/") return route.fulfill({ status: 201, json: { ...target, ...route.request().postDataJSON() } });
      if (path === "/auth/register/") return route.fulfill({ status: 201, json: { id: "new-user", email: "new@example.test", role: "viewer" } });
    }
    const data: Record<string, unknown> = {
      "/auth/me/": user,
      "/targets/": list([target]),
      "/scans/": list([scan]),
      "/scans/stats/": { total: state === "empty" ? 0 : 31, active: 3, by_status: { completed: 28, running: 2, pending: 1, failed: 0, cancelled: 0 }, findings_total: 11, findings_by_severity: severity, exploits_proven: 0 },
      "/scans/scan-1/": scan,
      "/scans/scan-1/findings/": [finding],
      "/scans/scan-1/services/": asset.services,
      "/scans/scan-1/owasp-coverage/": coverage,
      "/assets/": list([asset]),
      "/assets/asset-1/": asset,
      "/findings/": list([finding]),
      "/findings/grouped/": list([group]),
      "/vulnerabilities/": list([]),
      "/evidence/": list([evidence]),
      "/playbooks/": list([]),
      
      "/knowledge-base/": list([article]),
      "/reports/": list([report]),
      "/reports/report-1/download/": { target: target.value, evidence: "laboratory-only" },
      "/audit-logs/": list([{ id: "audit-1", user: "user-1", user_email: user.email, action: "report.created", severity: "info", source: "127.0.0.1", metadata: { scan: scan.id }, timestamp: date }]),
      "/risk/overview/": { summary: { assets: 1, findings: state === "empty" ? 0 : 11, severity: state === "empty" ? { critical: 0, high: 0, medium: 0, low: 0, info: 0 } : severity, risk_score: 42, risk_level: "medium" }, top_assets: state === "empty" ? [] : [{ asset: asset.id, hostname: asset.hostname, ip: asset.ip, domain: asset.domain, risk_score: 42, risk_level: "medium", severity, findings: 11 }], heatmap: state === "empty" ? [] : [{ category: "web-headers", category_label: "Headers de segurança", severity: "medium", count: 3 }], chains: [] },
    };
    return route.fulfill({ status: path in data ? 200 : 404, json: data[path] ?? { detail: "Fixture não encontrada: " + path } });
  });
}
