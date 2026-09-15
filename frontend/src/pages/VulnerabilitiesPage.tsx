/** Vulnerabilities — vulnerabilidades consolidadas + catálogo de CVEs (RF008). */

import { useMemo, useState } from "react";
import { Boxes, ExternalLink, Search, ShieldAlert } from "lucide-react";

import { PageHeader } from "@/components/PageHeader";
import { VulnerabilityGroupSheet } from "@/components/findings/VulnerabilityGroupSheet";
import { CategoryBadge } from "@/components/ui/category-badge";
import { DataPagination } from "@/components/ui/data-pagination";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Input } from "@/components/ui/input";
import { SeverityBadge, SEVERITY_LABELS, SEVERITY_ORDER } from "@/components/ui/severity-badge";
import { StatCard } from "@/components/ui/stat-card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import { useGroupedFindings, useRiskOverview, useVulnerabilities } from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { usePageTitle } from "@/hooks/usePageTitle";
import { errorMessage } from "@/lib/errors";
import type { GroupedFinding, Severity } from "@/lib/types";

const SEVERITY_ACCENT: Record<Severity, "danger" | "warning" | "primary" | "muted"> = {
  critical: "danger",
  high: "danger",
  medium: "warning",
  low: "primary",
  info: "muted",
};

function FindingsTab() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [page, setPage] = useState(1);
  const debounced = useDebounce(search);
  const [selected, setSelected] = useState<GroupedFinding | null>(null);

  const overview = useRiskOverview();
  const counts = overview.data?.summary.severity;

  const params = useMemo(
    () => ({
      search: debounced || undefined,
      severity: severity === "all" ? undefined : severity,
      page,
    }),
    [debounced, severity, page],
  );
  const { data, isLoading, isError, error } = useGroupedFindings(params);
  const results = data?.results ?? [];

  return (
    <div className="space-y-4">
      {/* KPIs de severidade — clicáveis para filtrar */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {SEVERITY_ORDER.map((sev) => (
          <StatCard
            key={sev}
            label={SEVERITY_LABELS[sev]}
            value={counts ? counts[sev] : "—"}
            accent={SEVERITY_ACCENT[sev]}
            loading={overview.isLoading}
            onClick={() => {
              setSeverity((cur) => (cur === sev ? "all" : sev));
              setPage(1);
            }}
          />
        ))}
      </div>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Buscar por título, categoria ou CVE…"
            className="pl-9"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button
            onClick={() => {
              setSeverity("all");
              setPage(1);
            }}
            className={cn(
              "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
              severity === "all"
                ? "border-primary/50 bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:text-foreground",
            )}
          >
            Todas
          </button>
          {SEVERITY_ORDER.map((sev) => (
            <button
              key={sev}
              onClick={() => {
                setSeverity(sev);
                setPage(1);
              }}
              className={cn(
                "rounded-full border px-3 py-1 text-xs font-medium capitalize transition-colors",
                severity === sev
                  ? "border-primary/50 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              {SEVERITY_LABELS[sev]}
            </button>
          ))}
        </div>
      </div>

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <TableSkeleton columns={6} />
      ) : results.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="Nenhuma vulnerabilidade encontrada"
          hint="Execute um scan de vulnerability (ou full) sobre um alvo mapeado para correlacionar CVEs e testar falhas ativas."
        />
      ) : (
        <>
          <div className="glass overflow-x-auto p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Vulnerabilidade</TableHead>
                  <TableHead>Severidade</TableHead>
                  <TableHead>Alvos afetados</TableHead>
                  <TableHead>Ocorrências</TableHead>
                  <TableHead>CVE / CWE</TableHead>
                  <TableHead>OWASP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.map((g) => (
                  <TableRow
                    key={`${g.category}:${g.title}`}
                    className="cursor-pointer"
                    onClick={() => setSelected(g)}
                  >
                    <TableCell className="max-w-md">
                      <p className="font-medium text-foreground">{g.title}</p>
                      <CategoryBadge category={g.category} className="mt-1" />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={g.severity} />
                    </TableCell>
                    <TableCell>
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-primary/40 bg-primary/10 px-2.5 py-0.5 text-xs font-semibold text-primary">
                        <Boxes className="h-3.5 w-3.5" />
                        {g.targets} {g.targets === 1 ? "alvo" : "alvos"}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-sm text-muted-foreground">
                      {g.occurrences}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-primary">
                      {g.cve ?? g.cwe ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {g.owasp_2025 || g.owasp_2021 || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
        </>
      )}

      <VulnerabilityGroupSheet group={selected} onOpenChange={(open) => !open && setSelected(null)} />
    </div>
  );
}

function CatalogTab() {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const debounced = useDebounce(search);

  const params = useMemo(
    () => ({ search: debounced || undefined, page }),
    [debounced, page],
  );
  const { data, isLoading, isError, error } = useVulnerabilities(params);
  const results = data?.results ?? [];

  return (
    <div className="space-y-4">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          placeholder="Buscar por CVE ou título…"
          className="pl-9"
        />
      </div>

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <TableSkeleton columns={4} />
      ) : results.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="Catálogo vazio"
          hint="Vulnerabilidades conhecidas aparecem aqui conforme os scans correlacionam CVEs."
        />
      ) : (
        <>
          <div className="glass overflow-x-auto p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE</TableHead>
                  <TableHead>Título</TableHead>
                  <TableHead>Severidade</TableHead>
                  <TableHead>CVSS</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.map((v) => (
                  <TableRow key={v.id}>
                    <TableCell>
                      {v.cve ? (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${v.cve}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-sm text-primary hover:underline"
                        >
                          {v.cve}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="max-w-md">{v.title}</TableCell>
                    <TableCell>
                      <SeverityBadge severity={v.severity} />
                    </TableCell>
                    <TableCell className="font-mono text-muted-foreground">
                      {v.cvss_score ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
        </>
      )}
    </div>
  );
}

export function VulnerabilitiesPage() {
  usePageTitle("Vulnerabilidades");
  return (
    <div>
      <PageHeader
        title="Vulnerabilidades"
        description="Cada vulnerabilidade lógica em uma linha — clique para ver como foi detectada, como explorá-la e todos os alvos afetados."
      />
      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="catalog">Catálogo CVE</TabsTrigger>
        </TabsList>
        <TabsContent value="findings" className="mt-4">
          <FindingsTab />
        </TabsContent>
        <TabsContent value="catalog" className="mt-4">
          <CatalogTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
