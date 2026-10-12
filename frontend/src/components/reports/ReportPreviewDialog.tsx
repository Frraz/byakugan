/** Pré-visualização in-app de um relatório (PDF via iframe, JSON formatado). */

import { useEffect, useState } from "react";
import { Download } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchBlob } from "@/lib/api";
import { errorMessage } from "@/lib/errors";
import type { Report } from "@/lib/types";

export function reportFilename(report: Report): string {
  return `byakugan-${report.report_type}-${report.id.slice(0, 8)}.${report.format}`;
}

export function ReportPreviewDialog({
  report,
  onOpenChange,
  onDownload,
}: {
  report: Report | null;
  onOpenChange: (open: boolean) => void;
  onDownload: (report: Report) => void;
}) {
  const [pdfUrl, setPdfUrl] = useState<string | null>(null);
  const [jsonText, setJsonText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!report) return;
    let objectUrl: string | null = null;
    let cancelled = false;

    setPdfUrl(null);
    setJsonText(null);
    setError(null);
    setLoading(true);

    fetchBlob(`/reports/${report.id}/download/`)
      .then(async (blob) => {
        if (cancelled) return;
        if (report.format === "pdf") {
          objectUrl = URL.createObjectURL(blob);
          setPdfUrl(objectUrl);
        } else if (report.format === "json") {
          const text = await blob.text();
          if (cancelled) return;
          try {
            setJsonText(JSON.stringify(JSON.parse(text), null, 2));
          } catch {
            setJsonText(text);
          }
        }
      })
      .catch((err) => !cancelled && setError(errorMessage(err)))
      .finally(() => !cancelled && setLoading(false));

    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [report, attempt]);

  return (
    <Dialog open={Boolean(report)} onOpenChange={onOpenChange}>
      <DialogContent className="flex h-[85dvh] max-w-4xl flex-col">
        <DialogHeader className="gap-3 pr-8 text-left sm:flex-row sm:items-start sm:justify-between sm:space-y-0">
          <div className="min-w-0 space-y-2">
            <DialogTitle className="leading-snug">
              Relatório {report?.report_type === "executive" ? "executivo" : "técnico"} ·{" "}
              <span className="font-mono uppercase">{report?.format}</span>
            </DialogTitle>
            <DialogDescription className="break-words">
              {report?.scan_target ?? "Scan de origem"}. Baixe o arquivo para consultar em outro aplicativo.
            </DialogDescription>
          </div>
          {report && (
            <Button className="shrink-0 self-start" size="sm" variant="outline" onClick={() => onDownload(report)}>
              <Download className="h-4 w-4" />
              Baixar
            </Button>
          )}
        </DialogHeader>

        <div className="min-h-0 flex-1 overflow-hidden rounded-lg border border-border" aria-busy={loading}>
          {loading ? (
            <div role="status" className="h-full">
              <span className="sr-only">Carregando pré-visualização…</span>
              <Skeleton className="h-full w-full" />
            </div>
          ) : error ? (
            <div className="space-y-3 p-4">
              <ErrorBanner message={error} />
              <Button variant="outline" onClick={() => setAttempt((value) => value + 1)}>
                Tentar novamente
              </Button>
            </div>
          ) : report?.format === "pdf" && pdfUrl ? (
            <iframe title="Pré-visualização do relatório" src={pdfUrl} className="h-full w-full" />
          ) : report?.format === "json" && jsonText ? (
            <pre className="thin-scroll h-full overflow-auto bg-popover p-4 font-mono text-xs text-foreground/90">
              {jsonText}
            </pre>
          ) : (
            <div className="flex h-full items-center justify-center p-6 text-center text-sm text-muted-foreground">
              A pré-visualização não está disponível para CSV. Use o botão “Baixar”.
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
