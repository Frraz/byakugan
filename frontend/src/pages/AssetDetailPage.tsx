/** Detalhe do ativo — serviços expostos (RF007). */

import { useParams } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";
import {
  EmptyState,
  ErrorBanner,
  GlassPanel,
  Skeleton,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useAsset } from "../hooks/useData";

export function AssetDetailPage() {
  const { id = "" } = useParams();
  const asset = useAsset(id);

  if (asset.isLoading) return <Skeleton className="h-40 w-full" />;
  if (asset.isError || !asset.data) return <ErrorBanner message="Ativo não encontrado." />;

  const a = asset.data;
  const services = a.services ?? [];
  const technologies = a.technologies ?? [];

  return (
    <div>
      <PageHeader title={a.hostname ?? a.ip ?? "Ativo"} description={a.domain ?? undefined} />

      <div className="grid gap-4 md:grid-cols-4">
        <GlassPanel>
          <p className="text-xs uppercase tracking-wide text-muted">IP</p>
          <p className="mt-1 font-mono text-primary">{a.ip ?? "—"}</p>
        </GlassPanel>
        <GlassPanel>
          <p className="text-xs uppercase tracking-wide text-muted">Hostname</p>
          <p className="mt-1">{a.hostname ?? "—"}</p>
        </GlassPanel>
        <GlassPanel>
          <p className="text-xs uppercase tracking-wide text-muted">SO</p>
          <p className="mt-1">{a.os ?? "—"}</p>
        </GlassPanel>
        <GlassPanel>
          <p className="text-xs uppercase tracking-wide text-muted">Status</p>
          <p className="mt-1 capitalize">{a.status}</p>
        </GlassPanel>
      </div>

      <h2 className="mb-3 mt-8 text-lg font-semibold text-foreground">Tecnologias</h2>
      {technologies.length === 0 ? (
        <EmptyState
          title="Nenhuma tecnologia"
          hint="Execute um scan de fingerprint para mapear as tecnologias deste ativo."
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Categoria</Th>
              <Th>Tecnologia</Th>
              <Th>Versão</Th>
              <Th>Confiança</Th>
              <Th>Evidência</Th>
            </tr>
          </thead>
          <tbody>
            {technologies.map((tech) => (
              <tr key={tech.id} className="hover:bg-white/5">
                <Td className="uppercase text-muted">{tech.category}</Td>
                <Td className="font-medium text-foreground">{tech.name}</Td>
                <Td className="font-mono text-primary">{tech.version ?? "—"}</Td>
                <Td className="capitalize text-muted">{tech.confidence}</Td>
                <Td className="text-muted">{tech.evidence || "—"}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <h2 className="mb-3 mt-8 text-lg font-semibold text-foreground">Serviços</h2>
      {services.length === 0 ? (
        <EmptyState title="Nenhum serviço" hint="Nenhum serviço exposto foi descoberto." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Porta</Th>
              <Th>Protocolo</Th>
              <Th>Serviço</Th>
              <Th>Produto</Th>
              <Th>Versão</Th>
            </tr>
          </thead>
          <tbody>
            {services.map((sv) => (
              <tr key={sv.id} className="hover:bg-white/5">
                <Td className="font-mono text-primary">{sv.port}</Td>
                <Td className="uppercase text-muted">{sv.protocol}</Td>
                <Td>{sv.service_name}</Td>
                <Td className="text-muted">{sv.product ?? "—"}</Td>
                <Td className="text-muted">{sv.version ?? "—"}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
