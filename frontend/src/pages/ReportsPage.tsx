/** Reports — gera e baixa relatórios executivos/técnicos de scans concluídos (RF009/RF010). */

import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";
import {
  Button,
  EmptyState,
  ErrorBanner,
  Field,
  GlassPanel,
  Select,
  Skeleton,
  Table,
  Td,
  Th,
} from "../components/ui";
import {
  useCreateReport,
  useDeleteReport,
  useDownloadReport,
  useReports,
  useScans,
} from "../hooks/useData";
import { useAuthStore } from "../store/auth";
import type { Report, ReportFormat, ReportType } from "../lib/types";

function reportFilename(report: Report): string {
  return `byakugan-${report.report_type}-${report.id.slice(0, 8)}.${report.format}`;
}

export function ReportsPage() {
  const role = useAuthStore((s) => s.user?.role);
  const canWrite = role === "analyst" || role === "admin";
  const isAdmin = role === "admin";
  const [open, setOpen] = useState(false);

  const { data, isLoading } = useReports();
  const scans = useScans({ status: "completed" });
  const deleteReport = useDeleteReport();
  const download = useDownloadReport();

  const reports = data?.results ?? [];
  const scanTargetById = new Map((scans.data?.results ?? []).map((s) => [s.id, s.target]));

  return (
    <div>
      <PageHeader
        title="Reports"
        description="Relatórios executivos e técnicos gerados a partir de scans concluídos."
        actions={
          canWrite && (
            <Button onClick={() => setOpen((v) => !v)} variant={open ? "ghost" : "primary"}>
              {open ? "Fechar" : "+ Gerar relatório"}
            </Button>
          )
        }
      />

      {open && canWrite && <ReportForm onDone={() => setOpen(false)} />}

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : reports.length === 0 ? (
        <EmptyState
          title="Nenhum relatório"
          hint="Gere um relatório a partir de um scan concluído."
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Alvo</Th>
              <Th>Tipo</Th>
              <Th>Formato</Th>
              <Th>Criado</Th>
              <Th />
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id} className="hover:bg-white/5">
                <Td>
                  <Link to={`/scans/${r.scan}`} className="font-medium text-primary hover:underline">
                    {scanTargetById.get(r.scan) ?? r.scan.slice(0, 8)}
                  </Link>
                </Td>
                <Td className="capitalize text-muted">{r.report_type}</Td>
                <Td className="uppercase text-muted">{r.format}</Td>
                <Td className="text-muted">{new Date(r.created_at).toLocaleString("pt-BR")}</Td>
                <Td className="flex justify-end gap-2 text-right">
                  <Button
                    variant="ghost"
                    disabled={download.isPending}
                    onClick={() => download.mutate({ id: r.id, filename: reportFilename(r) })}
                  >
                    Baixar
                  </Button>
                  {isAdmin && (
                    <Button variant="danger" onClick={() => deleteReport.mutate(r.id)}>
                      Excluir
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}

function ReportForm({ onDone }: { onDone: () => void }) {
  const create = useCreateReport();
  const { data: scansData } = useScans({ status: "completed" });
  const scans = scansData?.results ?? [];

  const [scan, setScan] = useState("");
  const [reportType, setReportType] = useState<ReportType>("executive");
  const [format, setFormat] = useState<ReportFormat>("pdf");

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate(
      { scan, report_type: reportType, format },
      { onSuccess: onDone }
    );
  };

  return (
    <GlassPanel className="mb-6">
      <form onSubmit={onSubmit} className="space-y-4">
        {scans.length === 0 ? (
          <EmptyState
            title="Nenhum scan concluído"
            hint="Um relatório só pode ser gerado a partir de um scan com status concluído (RN012)."
          />
        ) : (
          <>
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="Scan (concluído)">
                <Select required value={scan} onChange={(e) => setScan(e.target.value)}>
                  <option value="">Selecione…</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target} — {new Date(s.created_at).toLocaleDateString("pt-BR")}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Tipo de relatório">
                <Select value={reportType} onChange={(e) => setReportType(e.target.value as ReportType)}>
                  <option value="executive">Executivo</option>
                  <option value="technical">Técnico</option>
                </Select>
              </Field>
              <Field label="Formato">
                <Select value={format} onChange={(e) => setFormat(e.target.value as ReportFormat)}>
                  <option value="pdf">PDF</option>
                  <option value="csv">CSV</option>
                  <option value="json">JSON</option>
                </Select>
              </Field>
            </div>

            {create.isError && <ErrorBanner message={(create.error as Error).message} />}

            <Button type="submit" disabled={create.isPending || !scan}>
              {create.isPending ? "Gerando…" : "Gerar relatório"}
            </Button>
          </>
        )}
      </form>
    </GlassPanel>
  );
}
