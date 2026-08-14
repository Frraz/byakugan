/** Scans — visão geral (KPIs), filtros claros, tabela rica e ações por scan. */

import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  Crosshair,
  MoreHorizontal,
  Plus,
  Radar,
  Search,
  ShieldAlert,
  Trash2,
  X,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/PageHeader";
import { ScanDeleteDialog } from "@/components/scans/ScanDeleteDialog";
import { ScanFormDialog } from "@/components/scans/ScanFormDialog";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { ScanTypeBadge } from "@/components/scans/ScanTypeBadge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { DataPagination } from "@/components/ui/data-pagination";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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
import { SeveritySummary } from "@/components/ui/severity-summary";
import { StatCard } from "@/components/ui/stat-card";
import { StatusBadge, SCAN_STATUS_LABELS } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useCancelScan, useScans, useScansStats, useTriggerExploit } from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { usePageTitle } from "@/hooks/usePageTitle";
import { usePermissions } from "@/hooks/usePermissions";
import { errorMessage } from "@/lib/errors";
import { formatDateTime, formatDuration, formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Scan, ScanStatus } from "@/lib/types";

const isActive = (s: Scan) => s.status === "pending" || s.status === "running";

/** Ordem das pills de status (com "Todos" no início). */
const STATUS_ORDER: ScanStatus[] = ["pending", "running", "completed", "failed", "cancelled"];

export function ScansPage() {
  usePageTitle("Scans");
  const { canWrite, isAdmin } = usePermissions();

  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<ScanStatus | "all">("all");
  const [scanType, setScanType] = useState("all");
  const [page, setPage] = useState(1);
  const debouncedSearch = useDebounce(search);

  const [formOpen, setFormOpen] = useState(false);
  const [deleting, setDeleting] = useState<Scan | null>(null);
  const [cancelling, setCancelling] = useState<Scan | null>(null);

  const cancel = useCancelScan();
  const exploit = useTriggerExploit();
  const stats = useScansStats();

  const params = useMemo(
    () => ({
      search: debouncedSearch || undefined,
      status: status === "all" ? undefined : status,
      scan_type: scanType === "all" ? undefined : scanType,
      page,
    }),
    [debouncedSearch, status, scanType, page],
  );

  const { data, isLoading, isError, error } = useScans(params);
  const scans = data?.results ?? [];
  const filtersActive = Boolean(search) || status !== "all" || scanType !== "all";

  const setStatusFilter = (next: ScanStatus | "all") => {
    setStatus(next);
    setPage(1);
  };

  const clearFilters = () => {
    setSearch("");
    setStatus("all");
    setScanType("all");
    setPage(1);
  };

  const onExploit = (s: Scan) => {
    exploit.mutate(s.id, {
      onSuccess: () => toast.success("Exploração enfileirada — acompanhe em Evidências."),
      onError: (err) => toast.error(errorMessage(err)),
    });
  };

  const s = stats.data;

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Descoberta autorizada de ativos, serviços e vulnerabilidades — e prova de impacto."
        actions={
          canWrite && (
            <Button onClick={() => setFormOpen(true)}>
              <Plus className="h-4 w-4" />
              Novo scan
            </Button>
          )
        }
      />

      {/* KPIs de visão geral */}
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label="Total de scans"
          value={s ? s.total : "—"}
          icon={Radar}
          accent="primary"
          onClick={filtersActive ? clearFilters : undefined}
          hint={filtersActive ? "limpar filtros" : undefined}
        />
        <StatCard
          label="Em execução"
          value={s ? s.active : "—"}
          icon={Activity}
          accent={s && s.active > 0 ? "primary" : "muted"}
          hint={s && s.active > 0 ? "ativos agora" : "nenhum ativo"}
          onClick={() => setStatusFilter(status === "running" ? "all" : "running")}
        />
        <StatCard
          label="Findings"
          value={s ? s.findings_total : "—"}
          icon={ShieldAlert}
          accent={s && s.findings_by_severity.critical > 0 ? "danger" : "warning"}
          hint={s ? `${s.findings_by_severity.critical} críticos` : undefined}
        />
        <StatCard
          label="Exploits provados"
          value={s ? s.exploits_proven : "—"}
          icon={Crosshair}
          accent={s && s.exploits_proven > 0 ? "danger" : "muted"}
          hint="prova de impacto"
        />
      </div>

      {/* Filtros: busca + tipo + pills de status com contagem */}
      <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Buscar por alvo…"
            className="pl-9"
          />
        </div>
        <Select
          value={scanType}
          onValueChange={(v) => {
            setScanType(v);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-full sm:w-44">
            <SelectValue placeholder="Tipo" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Todos os tipos</SelectItem>
            <SelectItem value="discovery">Discovery</SelectItem>
            <SelectItem value="fingerprint">Fingerprint</SelectItem>
            <SelectItem value="vulnerability">Vulnerability</SelectItem>
            <SelectItem value="full">Full</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        <StatusPill active={status === "all"} onClick={() => setStatusFilter("all")}>
          Todos {s ? <Count>{s.total}</Count> : null}
        </StatusPill>
        {STATUS_ORDER.map((st) => (
          <StatusPill key={st} active={status === st} onClick={() => setStatusFilter(st)}>
            {SCAN_STATUS_LABELS[st]} {s ? <Count>{s.by_status[st]}</Count> : null}
          </StatusPill>
        ))}
        {filtersActive && (
          <button
            onClick={clearFilters}
            className="inline-flex items-center gap-1 rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <X className="h-3 w-3" />
            Limpar
          </button>
        )}
      </div>

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <TableSkeleton columns={6} />
      ) : scans.length === 0 ? (
        <EmptyState
          icon={Radar}
          title="Nenhum scan encontrado"
          hint={
            filtersActive
              ? "Ajuste os filtros para ver mais resultados."
              : "Inicie uma descoberta a partir de um alvo autorizado."
          }
          action={
            canWrite &&
            (filtersActive ? (
              <Button variant="secondary" onClick={clearFilters}>
                <X className="h-4 w-4" />
                Limpar filtros
              </Button>
            ) : (
              <Button onClick={() => setFormOpen(true)}>
                <Plus className="h-4 w-4" />
                Novo scan
              </Button>
            ))
          }
        />
      ) : (
        <div className="space-y-4">
          <div className="glass overflow-x-auto p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Alvo</TableHead>
                  <TableHead>Tipo</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Duração</TableHead>
                  <TableHead>Criado</TableHead>
                  {canWrite && <TableHead className="w-10" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => (
                  <TableRow key={scan.id} className={cn(isActive(scan) && "bg-primary/5")}>
                    <TableCell>
                      <Link
                        to={`/scans/${scan.id}`}
                        className="group inline-flex items-start gap-2"
                      >
                        <Radar className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground group-hover:text-primary" />
                        <span className="min-w-0">
                          <span className="block font-medium text-foreground group-hover:text-primary group-hover:underline">
                            {scan.target_name ?? scan.target}
                          </span>
                          {scan.target_name && (
                            <span className="block font-mono text-xs text-muted-foreground">
                              {scan.target}
                            </span>
                          )}
                        </span>
                      </Link>
                    </TableCell>
                    <TableCell>
                      <ScanTypeBadge type={scan.scan_type} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={scan.status} />
                      {isActive(scan) && (
                        <ScanProgress progress={scan.progress} phase={scan.phase} className="mt-1.5 w-40" />
                      )}
                      {scan.status === "failed" && scan.failure_reason && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <p className="mt-1 max-w-[12rem] truncate text-xs text-destructive/80">
                              {scan.failure_reason}
                            </p>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-xs">{scan.failure_reason}</TooltipContent>
                        </Tooltip>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <SeveritySummary counts={scan.severity_counts} />
                        {scan.findings_count > 0 && (
                          <span className="text-xs tabular-nums text-muted-foreground">
                            ({scan.findings_count})
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {scan.started_at
                        ? formatDuration(scan.started_at, scan.finished_at ?? new Date())
                        : "—"}
                    </TableCell>
                    <TableCell>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="text-sm text-muted-foreground">
                            {formatRelative(scan.created_at)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{formatDateTime(scan.created_at)}</TooltipContent>
                      </Tooltip>
                    </TableCell>
                    {canWrite && (
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" aria-label="Ações do scan">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            {isActive(scan) && (
                              <DropdownMenuItem onClick={() => setCancelling(scan)}>
                                <XCircle className="h-4 w-4" />
                                Cancelar
                              </DropdownMenuItem>
                            )}
                            {scan.status === "completed" && (
                              <DropdownMenuItem
                                disabled={exploit.isPending}
                                onClick={() => onExploit(scan)}
                              >
                                <Crosshair className="h-4 w-4" />
                                Explorar (prova de impacto)
                              </DropdownMenuItem>
                            )}
                            {isAdmin && (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <span>
                                    <DropdownMenuItem
                                      disabled={isActive(scan)}
                                      className="text-destructive focus:text-destructive"
                                      onClick={() => setDeleting(scan)}
                                    >
                                      <Trash2 className="h-4 w-4" />
                                      Excluir
                                    </DropdownMenuItem>
                                  </span>
                                </TooltipTrigger>
                                {isActive(scan) && (
                                  <TooltipContent>Cancele o scan antes de excluir</TooltipContent>
                                )}
                              </Tooltip>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
        </div>
      )}

      <ScanFormDialog open={formOpen} onOpenChange={setFormOpen} />
      <ScanDeleteDialog
        scan={deleting}
        onOpenChange={(open) => !open && setDeleting(null)}
        onDeleted={() => {
          toast.success("Scan excluído.");
          setDeleting(null);
        }}
      />
      <ConfirmDialog
        open={Boolean(cancelling)}
        onOpenChange={(open) => !open && setCancelling(null)}
        title="Cancelar scan"
        confirmLabel="Cancelar scan"
        cancelLabel="Voltar"
        variant="destructive"
        loading={cancel.isPending}
        description={
          cancelling && (
            <p>
              O scan de <span className="font-mono text-foreground">{cancelling.target}</span> será
              interrompido.
            </p>
          )
        }
        onConfirm={() => {
          if (!cancelling) return;
          cancel.mutate(cancelling.id, {
            onSuccess: () => {
              toast.success("Scan cancelado.");
              setCancelling(null);
            },
            onError: (err) => toast.error(errorMessage(err)),
          });
        }}
      />
    </div>
  );
}

/** Pill de filtro de status (segmented control). */
function StatusPill({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors",
        active
          ? "border-primary/50 bg-primary/10 text-primary"
          : "border-border text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

/** Contador dentro de uma pill. */
function Count({ children }: { children: ReactNode }) {
  return <span className="rounded-full bg-current/15 px-1.5 text-[10px] tabular-nums">{children}</span>;
}
