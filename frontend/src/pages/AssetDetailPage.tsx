/** Detalhe do ativo — serviços, tecnologias e findings em abas (RF007). */

import { useState } from "react";
import { ArrowLeft } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { PageHeader } from "@/components/PageHeader";
import { FindingDetailSheet } from "@/components/findings/FindingDetailSheet";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import { GlassPanel } from "@/components/ui/glass-panel";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAsset, useFindings } from "@/hooks/useData";
import { usePageTitle } from "@/hooks/usePageTitle";
import type { Finding } from "@/lib/types";

export function AssetDetailPage() {
  const { id = "" } = useParams();
  const asset = useAsset(id);
  const findings = useFindings({ asset: id });
  const [selected, setSelected] = useState<Finding | null>(null);

  usePageTitle(asset.data ? `Ativo · ${asset.data.hostname ?? asset.data.ip ?? ""}` : "Ativo");

  if (asset.isLoading) return <Skeleton className="h-64 w-full rounded-2xl" />;
  if (asset.isError || !asset.data) return <ErrorBanner message="Ativo não encontrado." />;

  const a = asset.data;
  const services = a.services ?? [];
  const technologies = a.technologies ?? [];
  const findingList = findings.data?.results ?? [];

  return (
    <div>
      <Link
        to="/assets"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        Voltar para assets
      </Link>

      <PageHeader title={a.hostname ?? a.ip ?? "Ativo"} description={a.domain ?? undefined} />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: "IP", value: a.ip ?? "—", mono: true },
          { label: "Hostname", value: a.hostname ?? "—" },
          { label: "SO", value: a.os ?? "—" },
          { label: "Status", value: a.status === "active" ? "Ativo" : "Inativo" },
        ].map((item) => (
          <GlassPanel key={item.label}>
            <p className="text-xs uppercase tracking-wide text-muted-foreground">{item.label}</p>
            <p className={`mt-1 ${item.mono ? "font-mono text-primary" : "text-foreground"}`}>
              {item.value}
            </p>
          </GlassPanel>
        ))}
      </div>

      <Tabs defaultValue="findings" className="mt-8">
        <TabsList>
          <TabsTrigger value="findings">Findings ({findingList.length})</TabsTrigger>
          <TabsTrigger value="services">Serviços ({services.length})</TabsTrigger>
          <TabsTrigger value="technologies">Tecnologias ({technologies.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="mt-4">
          {findings.isLoading ? (
            <Skeleton className="h-32 w-full rounded-2xl" />
          ) : findingList.length === 0 ? (
            <EmptyState
              title="Nenhum finding"
              hint="Execute um scan de vulnerability (ou full) para correlacionar CVEs conhecidos."
            />
          ) : (
            <div className="glass overflow-x-auto p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Finding</TableHead>
                    <TableHead>Severidade</TableHead>
                    <TableHead>CVSS</TableHead>
                    <TableHead>Categoria</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingList.map((f) => (
                    <TableRow key={f.id} className="cursor-pointer" onClick={() => setSelected(f)}>
                      <TableCell className="font-medium text-foreground">{f.title}</TableCell>
                      <TableCell>
                        <SeverityBadge severity={f.severity} />
                      </TableCell>
                      <TableCell className="font-mono text-muted-foreground">
                        {f.cvss ?? "—"}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{f.category}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        <TabsContent value="services" className="mt-4">
          {services.length === 0 ? (
            <EmptyState title="Nenhum serviço" hint="Nenhum serviço exposto foi descoberto." />
          ) : (
            <div className="glass overflow-x-auto p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Porta</TableHead>
                    <TableHead>Protocolo</TableHead>
                    <TableHead>Serviço</TableHead>
                    <TableHead>Produto</TableHead>
                    <TableHead>Versão</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {services.map((sv) => (
                    <TableRow key={sv.id}>
                      <TableCell className="font-mono text-primary">{sv.port}</TableCell>
                      <TableCell className="uppercase text-muted-foreground">{sv.protocol}</TableCell>
                      <TableCell>{sv.service_name}</TableCell>
                      <TableCell className="text-muted-foreground">{sv.product ?? "—"}</TableCell>
                      <TableCell className="font-mono text-muted-foreground">
                        {sv.version ?? "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        <TabsContent value="technologies" className="mt-4">
          {technologies.length === 0 ? (
            <EmptyState
              title="Nenhuma tecnologia"
              hint="Execute um scan de fingerprint para mapear as tecnologias deste ativo."
            />
          ) : (
            <div className="glass overflow-x-auto p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Categoria</TableHead>
                    <TableHead>Tecnologia</TableHead>
                    <TableHead>Versão</TableHead>
                    <TableHead>Confiança</TableHead>
                    <TableHead>Evidência</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {technologies.map((tech) => (
                    <TableRow key={tech.id}>
                      <TableCell className="uppercase text-muted-foreground">
                        {tech.category}
                      </TableCell>
                      <TableCell className="font-medium text-foreground">{tech.name}</TableCell>
                      <TableCell className="font-mono text-primary">{tech.version ?? "—"}</TableCell>
                      <TableCell className="capitalize text-muted-foreground">
                        {tech.confidence}
                      </TableCell>
                      <TableCell className="max-w-xs truncate text-muted-foreground">
                        {tech.evidence || "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>
      </Tabs>

      <FindingDetailSheet finding={selected} onOpenChange={(open) => !open && setSelected(null)} />
    </div>
  );
}
