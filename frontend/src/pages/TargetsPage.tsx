/** Targets — cadastro, edição e exclusão de alvos autorizados (RF004, RN001/RN006/RN007). */

import { useMemo, useState } from "react";
import { AlertTriangle, MoreHorizontal, Pencil, Plus, Search, Target as TargetIcon, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/PageHeader";
import { TargetDeleteDialog } from "@/components/targets/TargetDeleteDialog";
import { TargetFormDialog } from "@/components/targets/TargetFormDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useTargets } from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { usePageTitle } from "@/hooks/usePageTitle";
import { usePermissions } from "@/hooks/usePermissions";
import { errorMessage } from "@/lib/errors";
import { formatDate, formatRelative } from "@/lib/format";
import type { Target, TargetKind } from "@/lib/types";

const KIND_LABELS: Record<TargetKind, string> = {
  host: "Host",
  domain: "Domínio",
  ip: "IP",
  cidr: "CIDR",
};

function isExpired(target: Target): boolean {
  return Boolean(
    target.authorization_expires_at && new Date(target.authorization_expires_at) < new Date(),
  );
}

export function TargetsPage() {
  usePageTitle("Targets");
  const { canWrite, isAdmin } = usePermissions();

  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("all");
  const [active, setActive] = useState("all");
  const [page, setPage] = useState(1);
  const debouncedSearch = useDebounce(search);

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Target | null>(null);
  const [deleting, setDeleting] = useState<Target | null>(null);

  const params = useMemo(
    () => ({
      search: debouncedSearch || undefined,
      kind: kind === "all" ? undefined : kind,
      is_active: active === "all" ? undefined : active,
      page,
    }),
    [debouncedSearch, kind, active, page],
  );

  const { data, isLoading, isError, error } = useTargets(params);
  const targets = data?.results ?? [];

  const openCreate = () => {
    setEditing(null);
    setFormOpen(true);
  };
  const openEdit = (target: Target) => {
    setEditing(target);
    setFormOpen(true);
  };

  const resetToFirstPage = <T,>(setter: (v: T) => void) => (value: T) => {
    setter(value);
    setPage(1);
  };

  return (
    <div>
      <PageHeader
        title="Targets"
        description="Alvos autorizados. Toda varredura exige autorização documentada (RN007)."
        actions={
          canWrite && (
            <Button onClick={openCreate}>
              <Plus className="h-4 w-4" />
              Novo alvo
            </Button>
          )
        }
      />

      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => resetToFirstPage(setSearch)(e.target.value)}
            placeholder="Buscar por nome ou valor…"
            className="pl-9"
          />
        </div>
        <Select value={kind} onValueChange={resetToFirstPage(setKind)}>
          <SelectTrigger className="w-full sm:w-40">
            <SelectValue placeholder="Tipo" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Todos os tipos</SelectItem>
            <SelectItem value="host">Host</SelectItem>
            <SelectItem value="domain">Domínio</SelectItem>
            <SelectItem value="ip">IP</SelectItem>
            <SelectItem value="cidr">CIDR</SelectItem>
          </SelectContent>
        </Select>
        <Select value={active} onValueChange={resetToFirstPage(setActive)}>
          <SelectTrigger className="w-full sm:w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Todos</SelectItem>
            <SelectItem value="true">Ativos</SelectItem>
            <SelectItem value="false">Inativos</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <TableSkeleton columns={6} />
      ) : targets.length === 0 ? (
        <EmptyState
          icon={TargetIcon}
          title="Nenhum alvo encontrado"
          hint={
            search || kind !== "all" || active !== "all"
              ? "Ajuste os filtros para ver mais resultados."
              : "Cadastre um alvo autorizado para iniciar as varreduras."
          }
          action={
            canWrite && (
              <Button onClick={openCreate}>
                <Plus className="h-4 w-4" />
                Novo alvo
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
                  <TableHead>Nome</TableHead>
                  <TableHead>Valor</TableHead>
                  <TableHead>Tipo</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Autorização</TableHead>
                  <TableHead className="text-right">Scans</TableHead>
                  <TableHead>Criado</TableHead>
                  {canWrite && <TableHead className="w-10" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">{t.name}</TableCell>
                    <TableCell className="font-mono text-primary">{t.value}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{KIND_LABELS[t.kind]}</Badge>
                    </TableCell>
                    <TableCell>
                      {t.is_active ? (
                        <span className="inline-flex items-center gap-1.5 text-sm text-success">
                          <span className="h-1.5 w-1.5 rounded-full bg-current" />
                          Ativo
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-sm text-muted-foreground">
                          <span className="h-1.5 w-1.5 rounded-full bg-current" />
                          Inativo
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {t.authorization_expires_at ? (
                        isExpired(t) ? (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="inline-flex items-center gap-1.5 text-sm text-destructive">
                                <AlertTriangle className="h-3.5 w-3.5" />
                                Expirada
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>
                              Expirou em {formatDate(t.authorization_expires_at)}
                            </TooltipContent>
                          </Tooltip>
                        ) : (
                          <span className="text-sm text-muted-foreground">
                            até {formatDate(t.authorization_expires_at)}
                          </span>
                        )
                      ) : (
                        <span className="text-sm text-muted-foreground">Sem expiração</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{t.scans_count}</TableCell>
                    <TableCell>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="text-sm text-muted-foreground">
                            {formatRelative(t.created_at)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{formatDate(t.created_at)}</TooltipContent>
                      </Tooltip>
                    </TableCell>
                    {canWrite && (
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" aria-label="Ações do alvo">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => openEdit(t)}>
                              <Pencil className="h-4 w-4" />
                              Editar
                            </DropdownMenuItem>
                            {isAdmin && (
                              <DropdownMenuItem
                                className="text-destructive focus:text-destructive"
                                onClick={() => setDeleting(t)}
                              >
                                <Trash2 className="h-4 w-4" />
                                Excluir
                              </DropdownMenuItem>
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

      <TargetFormDialog open={formOpen} onOpenChange={setFormOpen} target={editing} />
      <TargetDeleteDialog
        target={deleting}
        onOpenChange={(open) => !open && setDeleting(null)}
        onDeleted={() => {
          toast.success("Alvo excluído.");
          setDeleting(null);
        }}
      />
    </div>
  );
}
