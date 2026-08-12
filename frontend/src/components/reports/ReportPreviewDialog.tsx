/** Pré-visualização in-app de um relatório (PDF via iframe, JSON formatado). */

import { useEffect, useState } from "react";
import { Download } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
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
  }, [report]);

  return (
    <Dialog open={Boolean(report)} onOpenChange={onOpenChange}>
      <DialogContent className="flex h-[85vh] max-w-4xl flex-col">
        <DialogHeader className="flex-row items-center justify-between gap-4 space-y-0">
          <DialogTitle>
            Relatório {report?.report_type === "executive" ? "executivo" : "técnico"} ·{" "}
            <span className="font-mono uppercase">{report?.format}</span>
          </DialogTitle>
          {report && (
            <Button size="sm" variant="outline" onClick={() => onDownload(report)}>
              <Download className="h-4 w-4" />
              Baixar
            </Button>
          )}
        </DialogHeader>

        <div className="min-h-0 flex-1 overflow-hidden rounded-xl border border-border">
          {loading ? (
            <Skeleton className="h-full w-full" />
          ) : error ? (
            <div className="p-4">
              <ErrorBanner message={error} />
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
