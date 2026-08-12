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
import type { ReportFormat, ReportType } from "@/lib/types";

const FORMAT_ICON = { pdf: FileText, csv: Table2, json: Braces };

export function ReportFormDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const create = useCreateReport();
  const { data: scansData } = useScans({ status: "completed" });
  const scans = scansData?.results ?? [];

  const [scan, setScan] = useState("");
  const [reportType, setReportType] = useState<ReportType>("executive");
  const [format, setFormat] = useState<ReportFormat>("pdf");

  useEffect(() => {
    if (open) {
      setScan("");
      setReportType("executive");
      setFormat("pdf");
    }
  }, [open]);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
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
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Gerar relatório</DialogTitle>
          <DialogDescription>
            Relatórios só podem ser gerados a partir de scans concluídos (RN012).
          </DialogDescription>
        </DialogHeader>

        {scans.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="Nenhum scan concluído"
            hint="Conclua um scan para poder gerar um relatório."
          />
        ) : (
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label>Scan concluído</Label>
              <Select value={scan} onValueChange={setScan}>
                <SelectTrigger>
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
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Tipo</Label>
                <Select value={reportType} onValueChange={(v) => setReportType(v as ReportType)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="executive">Executivo</SelectItem>
                    <SelectItem value="technical">Técnico</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Formato</Label>
                <Select value={format} onValueChange={(v) => setFormat(v as ReportFormat)}>
                  <SelectTrigger>
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
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Cancelar
              </Button>
              <Button type="submit" disabled={create.isPending || !scan}>
                {create.isPending ? "Gerando…" : "Gerar relatório"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
