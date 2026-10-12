/** Diálogo de geração de relatório (RF009/RF010, RN012). */

import { type FormEvent, useEffect, useState } from "react";
import { Braces, FileText, Table2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { DataPagination } from "@/components/ui/data-pagination";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useCreateReport, useScans } from "@/hooks/useData";
import { errorMessage } from "@/lib/errors";
import { formatDate } from "@/lib/format";
import type { ReportFormat, ReportType, Scan } from "@/lib/types";

const FORMAT_ICON = { pdf: FileText, csv: Table2, json: Braces };

export function ReportFormDialog({
  open,
  onOpenChange,
  initialScan,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialScan?: Scan;
}) {
  const create = useCreateReport();
  const resetCreate = create.reset;
  const [page, setPage] = useState(1);
  const { data: scansData, isLoading, isError, error, refetch } = useScans(
    { status: "completed", page }, open,
  );
  const available = scansData?.results ?? [];
  const scans = initialScan && !available.some((item) => item.id === initialScan.id) ? [initialScan, ...available] : available;

  const [scan, setScan] = useState("");
  const [reportType, setReportType] = useState<ReportType>("executive");
  const [format, setFormat] = useState<ReportFormat>("pdf");

  useEffect(() => {
    if (open) {
      resetCreate();
      setPage(1);
      setScan(initialScan?.id ?? "");
      setReportType("executive");
      setFormat("pdf");
    }
  }, [open, resetCreate, initialScan?.id]);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!scan || create.isPending) return;
    create.mutate(
      { scan, report_type: reportType, format },
      {
        onSuccess: () => {
          toast.success("Relatório gerado.");
          onOpenChange(false);
        },
        onError: (err) => toast.error(errorMessage(err)),
      },
    );
  };

  const FormatIcon = FORMAT_ICON[format];

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => !create.isPending && onOpenChange(nextOpen)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Gerar relatório</DialogTitle>
          <DialogDescription>
            Escolha um scan concluído e o documento adequado ao seu público.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <p role="status" className="py-8 text-center text-sm text-muted-foreground">
            Carregando scans concluídos…
          </p>
        ) : isError ? (
          <div className="space-y-3">
            <ErrorBanner message={errorMessage(error)} />
            <Button variant="outline" onClick={() => void refetch()}>Tentar novamente</Button>
          </div>
        ) : scans.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="Nenhum scan concluído"
            hint="Conclua um scan para poder gerar um relatório."
          />
        ) : (
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="report-scan">Scan concluído</Label>
              <Select value={scan} onValueChange={setScan}>
                <SelectTrigger id="report-scan" disabled={create.isPending}>
                  <SelectValue placeholder="Selecione um scan…" />
                </SelectTrigger>
                <SelectContent>
                  {scans.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.target} — {formatDate(s.created_at)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <DataPagination count={scansData?.count ?? 0} page={page} onPageChange={setPage} />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="report-type">Tipo</Label>
                <Select value={reportType} onValueChange={(v) => setReportType(v as ReportType)}>
                  <SelectTrigger id="report-type" disabled={create.isPending}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="executive">Executivo</SelectItem>
                    <SelectItem value="technical">Técnico</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="report-format">Formato</Label>
                <Select value={format} onValueChange={(v) => setFormat(v as ReportFormat)}>
                  <SelectTrigger id="report-format" disabled={create.isPending}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pdf">PDF</SelectItem>
                    <SelectItem value="csv">CSV</SelectItem>
                    <SelectItem value="json">JSON</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <p className="flex items-center gap-2 rounded-lg bg-secondary/50 px-3 py-2 text-xs text-muted-foreground">
              <FormatIcon className="h-4 w-4" />
              {reportType === "executive"
                ? "Resumo executivo: risco, top ativos e heatmap."
                : "Relatório técnico: inventário, findings detalhados e Knowledge Base."}
            </p>

            {create.isError && <ErrorBanner message={errorMessage(create.error)} />}

            <DialogFooter>
              <Button type="button" variant="ghost" disabled={create.isPending} onClick={() => onOpenChange(false)}>
                Cancelar
              </Button>
              <Button type="submit" disabled={create.isPending || !scan}>
                {create.isPending ? "Gerando…" : "Gerar relatório"}
              </Button>
            </DialogFooter>
            {create.isPending && (
              <p role="status" className="text-sm text-muted-foreground">
                Gerando documento. Aguarde a confirmação do servidor.
              </p>
            )}
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
