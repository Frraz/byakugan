/** Reports — gerar, pré-visualizar, baixar e excluir relatórios (RF009/RF010). */

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Braces, Download, Eye, FileBarChart, FileText, Plus, Table2, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/PageHeader";
import { ReportFormDialog } from "@/components/reports/ReportFormDialog";
import { ReportPreviewDialog, reportFilename } from "@/components/reports/ReportPreviewDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { DataPagination } from "@/components/ui/data-pagination";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { useDeleteReport, useDownloadReport, useReports } from "@/hooks/useData";
import { usePageTitle } from "@/hooks/usePageTitle";
import { usePermissions } from "@/hooks/usePermissions";
import { errorMessage } from "@/lib/errors";
import { formatBytes, formatDateTime } from "@/lib/format";
import type { Report, ReportFormat } from "@/lib/types";

const FORMAT_ICON: Record<ReportFormat, typeof FileText> = {
  pdf: FileText,
  csv: Table2,
  json: Braces,
};

export function ReportsPage() {
  usePageTitle("Relatórios");
  const { canWrite, isAdmin } = usePermissions();

  const [type, setType] = useState("all");
  const [format, setFormat] = useState("all");
  const [page, setPage] = useState(1);

  const [formOpen, setFormOpen] = useState(false);
  const [preview, setPreview] = useState<Report | null>(null);
  const [deleting, setDeleting] = useState<Report | null>(null);

  const download = useDownloadReport();
  const del = useDeleteReport();

  const params = useMemo(
    () => ({
      report_type: type === "all" ? undefined : type,
      format: format === "all" ? undefined : format,
      page,
    }),
    [type, format, page],
  );
  const { data, isLoading, isError, error } = useReports(params);
  const reports = data?.results ?? [];

  const onDownload = (r: Report) =>
    download.mutate(
      { id: r.id, filename: reportFilename(r) },
      { onError: (err) => toast.error(errorMessage(err)) },
    );

  const onPage = <T,>(setter: (v: T) => void) => (value: T) => {
    setter(value);
    setPage(1);
  };

  return (
    <div>
      <PageHeader
        title="Relatórios"
        description="Relatórios executivos e técnicos gerados a partir de scans concluídos."
        actions={
          canWrite && (
            <Button onClick={() => setFormOpen(true)}>
              <Plus className="h-4 w-4" />
              Gerar relatório
            </Button>
          )
        }
      />

      <div className="mb-4 flex flex-col gap-3 sm:flex-row">
        <Select value={type} onValueChange={onPage(setType)}>
          <SelectTrigger className="w-full sm:w-44">
            <SelectValue placeholder="Tipo" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Todos os tipos</SelectItem>
            <SelectItem value="executive">Executivo</SelectItem>
            <SelectItem value="technical">Técnico</SelectItem>
          </SelectContent>
        </Select>
        <Select value={format} onValueChange={onPage(setFormat)}>
          <SelectTrigger className="w-full sm:w-44">
            <SelectValue placeholder="Formato" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Todos os formatos</SelectItem>
            <SelectItem value="pdf">PDF</SelectItem>
            <SelectItem value="csv">CSV</SelectItem>
            <SelectItem value="json">JSON</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <TableSkeleton columns={5} />
      ) : reports.length === 0 ? (
        <EmptyState
          icon={FileBarChart}
          title="Nenhum relatório"
          hint="Gere um relatório a partir de um scan concluído."
          action={
            canWrite && (
              <Button onClick={() => setFormOpen(true)}>
                <Plus className="h-4 w-4" />
                Gerar relatório
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
                  <TableHead>Formato</TableHead>
                  <TableHead>Tamanho</TableHead>
                  <TableHead>Gerado</TableHead>
                  <TableHead className="text-right">Ações</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((r) => {
                  const FormatIcon = FORMAT_ICON[r.format];
                  const previewable = r.format === "pdf" || r.format === "json";
                  return (
                    <TableRow key={r.id}>
                      <TableCell>
                        <Link
                          to={`/scans/${r.scan}`}
                          className="font-medium text-primary hover:underline"
                        >
                          {r.scan_target ?? r.scan.slice(0, 8)}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <Badge variant={r.report_type === "executive" ? "secondary" : "outline"}>
                          {r.report_type === "executive" ? "Executivo" : "Técnico"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="inline-flex items-center gap-1.5 text-sm uppercase text-muted-foreground">
                          <FormatIcon className="h-4 w-4" />
                          {r.format}
                        </span>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatBytes(r.file_size)}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDateTime(r.created_at)}
                      </TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          {previewable && (
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label="Visualizar"
                              onClick={() => setPreview(r)}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label="Baixar"
                            disabled={download.isPending}
                            onClick={() => onDownload(r)}
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          {isAdmin && (
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label="Excluir"
                              className="hover:text-destructive"
                              onClick={() => setDeleting(r)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
          <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
        </div>
      )}

      <ReportFormDialog open={formOpen} onOpenChange={setFormOpen} />
      <ReportPreviewDialog
        report={preview}
        onOpenChange={(open) => !open && setPreview(null)}
        onDownload={onDownload}
      />
      <ConfirmDialog
        open={Boolean(deleting)}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Excluir relatório"
        variant="destructive"
        confirmLabel="Excluir"
        loading={del.isPending}
        description="O relatório e seu arquivo serão removidos permanentemente."
        onConfirm={() => {
          if (!deleting) return;
          del.mutate(deleting.id, {
            onSuccess: () => {
              toast.success("Relatório excluído.");
              setDeleting(null);
            },
            onError: (err) => toast.error(errorMessage(err)),
          });
        }}
      />
    </div>
  );
}
