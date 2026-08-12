/** Scans — listar (com filtros), criar, cancelar e excluir, com polling adaptativo. */

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { MoreHorizontal, Plus, Radar, Search, Trash2, XCircle } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/PageHeader";
import { ScanDeleteDialog } from "@/components/scans/ScanDeleteDialog";
import { ScanFormDialog } from "@/components/scans/ScanFormDialog";
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
import { StatusBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useCancelScan, useScans } from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { usePageTitle } from "@/hooks/usePageTitle";
import { usePermissions } from "@/hooks/usePermissions";
import { errorMessage } from "@/lib/errors";
import { formatDateTime, formatDuration, formatRelative } from "@/lib/format";
import type { Scan, ScanType } from "@/lib/types";

const SCAN_TYPE_LABELS: Record<ScanType, string> = {
  discovery: "Discovery",
  fingerprint: "Fingerprint",
  vulnerability: "Vulnerability",
  full: "Full",
};

const isActive = (s: Scan) => s.status === "pending" || s.status === "running";

export function ScansPage() {
  usePageTitle("Scans");
  const { canWrite, isAdmin } = usePermissions();

  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [scanType, setScanType] = useState("all");
  const [page, setPage] = useState(1);
  const debouncedSearch = useDebounce(search);

  const [formOpen, setFormOpen] = useState(false);
  const [deleting, setDeleting] = useState<Scan | null>(null);
  const [cancelling, setCancelling] = useState<Scan | null>(null);

  const cancel = useCancelScan();

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

  const onPage = <T,>(setter: (v: T) => void) => (value: T) => {
    setter(value);
    setPage(1);
  };

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Descoberta autorizada de ativos, serviços e vulnerabilidades."
        actions={
          canWrite && (
            <Button onClick={() => setFormOpen(true)}>
              <Plus className="h-4 w-4" />
              Novo scan
            </Button>
          )
        }
      />

      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => onPage(setSearch)(e.target.value)}
            placeholder="Buscar por alvo…"
            className="pl-9"
          />
        </div>
        <Select value={status} onValueChange={onPage(setStatus)}>
          <SelectTrigger className="w-full sm:w-44">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Todos os status</SelectItem>
            <SelectItem value="pending">Pendente</SelectItem>
            <SelectItem value="running">Executando</SelectItem>
            <SelectItem value="completed">Concluído</SelectItem>
            <SelectItem value="failed">Falhou</SelectItem>
            <SelectItem value="cancelled">Cancelado</SelectItem>
          </SelectContent>
        </Select>
        <Select value={scanType} onValueChange={onPage(setScanType)}>
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

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <TableSkeleton columns={6} />
      ) : scans.length === 0 ? (
        <EmptyState
          icon={Radar}
          title="Nenhum scan encontrado"
          hint={
            search || status !== "all" || scanType !== "all"
              ? "Ajuste os filtros para ver mais resultados."
              : "Inicie uma descoberta a partir de um alvo autorizado."
          }
          action={
            canWrite && (
              <Button onClick={() => setFormOpen(true)}>
                <Plus className="h-4 w-4" />
                Novo scan
              </Button>
            )
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
                {scans.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <Link
                        to={`/scans/${s.id}`}
                        className="font-medium text-primary hover:underline"
                      >
                        {s.target_name ?? s.target}
                      </Link>
                      {s.target_name && (
                        <p className="font-mono text-xs text-muted-foreground">{s.target}</p>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {SCAN_TYPE_LABELS[s.scan_type]}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={s.status} />
                    </TableCell>
                    <TableCell>
                      <SeveritySummary counts={s.severity_counts} />
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {s.started_at ? formatDuration(s.started_at, s.finished_at ?? new Date()) : "—"}
                    </TableCell>
                    <TableCell>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="text-sm text-muted-foreground">
                            {formatRelative(s.created_at)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{formatDateTime(s.created_at)}</TooltipContent>
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
                            {isActive(s) && (
                              <DropdownMenuItem onClick={() => setCancelling(s)}>
                                <XCircle className="h-4 w-4" />
                                Cancelar
                              </DropdownMenuItem>
                            )}
                            {isAdmin && (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <span>
                                    <DropdownMenuItem
                                      disabled={isActive(s)}
                                      className="text-destructive focus:text-destructive"
                                      onClick={() => setDeleting(s)}
                                    >
                                      <Trash2 className="h-4 w-4" />
                                      Excluir
                                    </DropdownMenuItem>
                                  </span>
                                </TooltipTrigger>
                                {isActive(s) && (
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
