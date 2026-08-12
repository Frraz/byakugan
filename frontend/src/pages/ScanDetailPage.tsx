/** Detalhe do scan — estado, autorização e findings (RN008). */

import { Link, useParams } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";
import {
  EmptyState,
  ErrorBanner,
  GlassPanel,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useScan, useScanFindings } from "../hooks/useData";

export function ScanDetailPage() {
  const { id = "" } = useParams();
  const scan = useScan(id);
  const findings = useScanFindings(id);

  if (scan.isLoading) return <Skeleton className="h-40 w-full" />;
  if (scan.isError || !scan.data) return <ErrorBanner message="Scan não encontrado." />;

  const s = scan.data;

  return (
    <div>
      <PageHeader
        title={s.target}
        description={`Scan ${s.scan_type}`}
        actions={<StatusBadge status={s.status} />}
      />

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <GlassPanel>
          <p className="text-xs uppercase tracking-wide text-muted">Autorizado por</p>
          <p className="mt-1 font-medium">{s.authorized_by}</p>
        </GlassPanel>
        <GlassPanel>
          <p className="text-xs uppercase tracking-wide text-muted">Escopo</p>
          <p className="mt-1 font-mono text-sm text-primary">{s.authorization_scope}</p>
        </GlassPanel>
        <GlassPanel>
          <p className="text-xs uppercase tracking-wide text-muted">Iniciado</p>
          <p className="mt-1 text-sm">{s.started_at ? new Date(s.started_at).toLocaleString("pt-BR") : "—"}</p>
        </GlassPanel>
        <GlassPanel>
          <p className="text-xs uppercase tracking-wide text-muted">Finalizado</p>
          <p className="mt-1 text-sm">{s.finished_at ? new Date(s.finished_at).toLocaleString("pt-BR") : "—"}</p>
        </GlassPanel>
      </div>

      {s.status === "failed" && s.failure_reason && (
        <div className="mt-4">
          <ErrorBanner message={s.failure_reason} />
        </div>
      )}

      <h2 className="mb-3 mt-8 text-lg font-semibold text-foreground">Findings</h2>
      {findings.isLoading ? (
        <Skeleton className="h-32 w-full" />
      ) : (findings.data ?? []).length === 0 ? (
        <EmptyState title="Nenhum finding" hint="Este scan não produziu findings." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Título</Th>
              <Th>Categoria</Th>
              <Th>Severidade</Th>
              <Th>CVSS</Th>
              <Th>Ativo</Th>
            </tr>
          </thead>
          <tbody>
            {findings.data!.map((f) => (
              <tr key={f.id} className="hover:bg-white/5">
                <Td className="font-medium">{f.title}</Td>
                <Td className="text-muted">{f.category}</Td>
                <Td>
                  <SeverityBadge severity={f.severity} />
                </Td>
                <Td className="text-muted">{f.cvss ?? "—"}</Td>
                <Td>
                  <Link to={`/assets/${f.asset}`} className="text-primary hover:underline">
                    ver ativo
                  </Link>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
