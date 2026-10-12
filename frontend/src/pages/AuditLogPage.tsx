/** Auditoria — trilha imutável de eventos sensíveis (admin-only, RN011). */

import { useMemo, useState } from "react";
import { Search, Shield } from "lucide-react";

import { PageHeader } from "@/components/PageHeader";
import { CopyButton } from "@/components/ui/copy-button";
import { DataPagination } from "@/components/ui/data-pagination";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { useAuditLogs } from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { usePageTitle } from "@/hooks/usePageTitle";
import { usePermissions } from "@/hooks/usePermissions";
import { errorMessage } from "@/lib/errors";
import { formatDateTime, formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { AuditLogEntry, AuditSeverity } from "@/lib/types";

const SEVERITY_LABELS: Record<AuditSeverity, string> = {
  info: "Informativo",
  warning: "Atenção",
  critical: "Crítico",
};

const SEVERITY_STYLES: Record<AuditSeverity, string> = {
  info: "bg-sev-info/15 text-sev-info border-sev-info/40",
  warning: "bg-warning/15 text-warning border-warning/40",
  critical: "bg-destructive/15 text-destructive border-destructive/40",
};

function AuditSeverityBadge({ severity }: { severity: AuditSeverity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        SEVERITY_STYLES[severity],
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

function EntryDetailSheet({
  entry,
  onOpenChange,
}: {
  entry: AuditLogEntry | null;
  onOpenChange: (open: boolean) => void;
}) {
  const metadataJson = entry ? JSON.stringify(entry.metadata, null, 2) : "";
  return (
    <Sheet open={Boolean(entry)} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="thin-scroll w-full overflow-y-auto sm:max-w-lg">
        {entry && (
          <div className="space-y-6">
            <SheetHeader className="space-y-3 text-left">
              <div className="flex flex-wrap items-center gap-2">
                <AuditSeverityBadge severity={entry.severity} />
                {entry.source && (
                  <span className="rounded-md border border-border px-2 py-0.5 font-mono text-xs text-muted-foreground">
                    {entry.source}
                  </span>
                )}
              </div>
              <SheetTitle className="break-all font-mono text-base leading-snug">
                {entry.action}
              </SheetTitle>
              <SheetDescription className="sr-only">Detalhe do evento de auditoria</SheetDescription>
            </SheetHeader>

            <section className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Contexto
              </h3>
              <div className="space-y-1.5 rounded-xl border border-border bg-popover/50 p-3 text-sm">
                <p>
                  <span className="text-muted-foreground">Ator: </span>
                  <span className="font-medium text-foreground">
                    {entry.user_email ?? "Sistema (sem usuário associado)"}
                  </span>
                </p>
                <p>
                  <span className="text-muted-foreground">Quando: </span>
                  <span className="font-medium text-foreground">{formatDateTime(entry.timestamp)}</span>
                </p>
              </div>
            </section>

            <section className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Detalhes (metadata)
                </h3>
                {Object.keys(entry.metadata ?? {}).length > 0 && (
                  <CopyButton value={metadataJson} label="Copiar detalhes" />
                )}
              </div>
              {Object.keys(entry.metadata ?? {}).length === 0 ? (
                <p className="text-sm text-muted-foreground">Nenhum detalhe adicional registrado.</p>
              ) : (
                <pre className="thin-scroll max-h-80 overflow-auto whitespace-pre-wrap rounded-xl border border-border bg-popover p-3 font-mono text-xs text-foreground/90">
                  {metadataJson}
                </pre>
              )}
            </section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

export function AuditLogPage() {
  usePageTitle("Auditoria");
  const { isAdmin } = usePermissions();

  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<AuditSeverity | "all">("all");
  const [page, setPage] = useState(1);
  const debounced = useDebounce(search);
  const [selected, setSelected] = useState<AuditLogEntry | null>(null);

  const params = useMemo(
    () => ({
      search: debounced || undefined,
      severity: severity === "all" ? undefined : severity,
      page,
    }),
    [debounced, severity, page],
  );
  const { data, isLoading, isError, error, refetch } = useAuditLogs(params, isAdmin);
  const results = data?.results ?? [];

  return (
    <div>
      <PageHeader
        title="Auditoria"
        description="Trilha imutável de eventos sensíveis — criação/cancelamento de scan, triagem, exportação, exclusão e exploração. Somente consulta: nenhum registro pode ser editado ou apagado pela aplicação."
      />

      {!isAdmin ? (
        <ErrorBanner message="Acesso restrito a administradores." />
      ) : (
        <>
          <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
                aria-label="Buscar por ação ou origem"
            placeholder="Buscar por ação ou origem…"
                className="pl-9"
              />
            </div>
            <Select
              value={severity}
              onValueChange={(v) => {
                setSeverity(v as AuditSeverity | "all");
                setPage(1);
              }}
            >
              <SelectTrigger aria-label="Filtrar por severidade" className="w-full sm:w-44">
                <SelectValue placeholder="Severidade" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Todas as severidades</SelectItem>
                <SelectItem value="info">Informativo</SelectItem>
                <SelectItem value="warning">Atenção</SelectItem>
                <SelectItem value="critical">Crítico</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {isError ? (
            <ErrorBanner message={errorMessage(error)} onRetry={() => void refetch()} />
          ) : isLoading ? (
            <TableSkeleton columns={5} />
          ) : results.length === 0 ? (
            <EmptyState
              icon={Shield}
              title="Nenhum evento encontrado"
              hint={
                search || severity !== "all"
                  ? "Ajuste os filtros para ver mais resultados."
                  : "Eventos sensíveis (scans, triagem, relatórios, exploração) aparecem aqui conforme ocorrem."
              }
            />
          ) : (
            <div className="space-y-4">
              <div className="glass overflow-x-auto p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Quando</TableHead>
                      <TableHead>Ator</TableHead>
                      <TableHead>Ação</TableHead>
                      <TableHead>Severidade</TableHead>
                      <TableHead>Origem</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {results.map((entry) => (
                      <TableRow
                        key={entry.id}
                        className="cursor-pointer"
                        onClick={() => setSelected(entry)}
                      >
                        <TableCell className="text-sm text-muted-foreground">
                          {formatRelative(entry.timestamp)}
                        </TableCell>
                        <TableCell className="text-foreground">
                          {entry.user_email ?? (
                            <span className="text-muted-foreground">Sistema</span>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-sm text-primary">{entry.action}</TableCell>
                        <TableCell>
                          <AuditSeverityBadge severity={entry.severity} />
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {entry.source ?? "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
            </div>
          )}
        </>
      )}

      <EntryDetailSheet entry={selected} onOpenChange={(open) => !open && setSelected(null)} />
    </div>
  );
}
