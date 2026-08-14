/** Detalhe do scan — timeline, resumo de severidade, findings, serviços e autorização. */

import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Crosshair, FileBarChart, Trash2, XCircle } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/PageHeader";
import { EvidenceStatusBadge, ImpactBadge } from "@/components/evidence/ImpactBadge";
import { ExploitationTimeline } from "@/components/evidence/ExploitationTimeline";
import { FindingDetailSheet } from "@/components/findings/FindingDetailSheet";
import { ScanDeleteDialog } from "@/components/scans/ScanDeleteDialog";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { ScanTypeBadge } from "@/components/scans/ScanTypeBadge";
import { Button } from "@/components/ui/button";
import { CategoryBadge } from "@/components/ui/category-badge";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import { GlassPanel } from "@/components/ui/glass-panel";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { SeverityBar } from "@/components/ui/severity-summary";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  useCancelScan,
  useEvidence,
  useScan,
  useScanFindings,
  useScanServices,
  useTriggerExploit,
} from "@/hooks/useData";
import { usePageTitle } from "@/hooks/usePageTitle";
import { usePermissions } from "@/hooks/usePermissions";
import { errorMessage } from "@/lib/errors";
import { formatDateTime, formatDuration } from "@/lib/format";
import type { Finding, SeverityCounts } from "@/lib/types";

function countSeverities(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

function TimelineStep({
  label,
  value,
  done,
}: {
  label: string;
  value: string;
  done: boolean;
}) {
  return (
    <div className="flex items-start gap-3">
      <span
        className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${done ? "bg-primary" : "bg-secondary"}`}
      />
      <div>
        <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
        <p className="text-sm text-foreground">{value}</p>
      </div>
    </div>
  );
}

export function ScanDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { canWrite, isAdmin } = usePermissions();
  const scan = useScan(id);
  const findings = useScanFindings(id);
  const services = useScanServices(id);
  const evidence = useEvidence({ scan: id });

  const [selected, setSelected] = useState<Finding | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const cancel = useCancelScan();
  const exploit = useTriggerExploit();

  usePageTitle(scan.data ? `Scan · ${scan.data.target}` : "Scan");

  if (scan.isLoading) return <Skeleton className="h-64 w-full rounded-2xl" />;
  if (scan.isError || !scan.data) return <ErrorBanner message="Scan não encontrado." />;

  const s = scan.data;
  const isActive = s.status === "pending" || s.status === "running";
  const findingList = findings.data ?? [];
  const counts = countSeverities(findingList);
  const evidenceList = evidence.data?.results ?? [];

  const onExploit = () =>
    exploit.mutate(s.id, {
      onSuccess: () => toast.success("Exploração enfileirada — os resultados aparecem aqui e em Evidências."),
      onError: (err) => toast.error(errorMessage(err)),
    });

  return (
    <div>
      <Link
        to="/scans"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        Voltar para scans
      </Link>

      <PageHeader
        title={s.target_name ?? s.target}
        description={s.target_name ? s.target : undefined}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ScanTypeBadge type={s.scan_type} />
            <StatusBadge status={s.status} />
            {s.status === "completed" && canWrite && (
              <Button
                variant="outline"
                size="sm"
                disabled={exploit.isPending}
                onClick={onExploit}
              >
                <Crosshair className="h-4 w-4" />
                Explorar
              </Button>
            )}
            {s.status === "completed" && (
              <Button variant="outline" size="sm" asChild>
                <Link to="/reports">
                  <FileBarChart className="h-4 w-4" />
                  Gerar relatório
                </Link>
              </Button>
            )}
            {canWrite && isActive && (
              <Button variant="outline" size="sm" onClick={() => setCancelling(true)}>
                <XCircle className="h-4 w-4" />
                Cancelar
              </Button>
            )}
            {isAdmin && !isActive && (
              <Button variant="destructive" size="sm" onClick={() => setDeleting(true)}>
                <Trash2 className="h-4 w-4" />
                Excluir
              </Button>
            )}
          </div>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        {/* Timeline */}
        <GlassPanel className="space-y-4">
          <h3 className="text-sm font-semibold text-foreground">Linha do tempo</h3>
          <div className="space-y-3">
            <TimelineStep label="Criado" value={formatDateTime(s.created_at)} done />
            <TimelineStep
              label="Iniciado"
              value={s.started_at ? formatDateTime(s.started_at) : "Aguardando…"}
              done={Boolean(s.started_at)}
            />
            <TimelineStep
              label="Finalizado"
              value={s.finished_at ? formatDateTime(s.finished_at) : "Em andamento…"}
              done={Boolean(s.finished_at)}
            />
          </div>
          {s.started_at && (
            <p className="border-t border-border pt-3 text-sm text-muted-foreground">
              Duração:{" "}
              <span className="font-medium text-foreground">
                {formatDuration(s.started_at, s.finished_at ?? new Date())}
              </span>
            </p>
          )}
          {isActive && (
            <ScanProgress
              progress={s.progress}
              phase={s.phase}
              className="border-t border-border pt-3"
            />
          )}
        </GlassPanel>

        {/* Resumo de severidade */}
        <GlassPanel className="space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground">Resumo de findings</h3>
            <span className="text-2xl font-bold tabular-nums text-foreground">
              {findingList.length}
            </span>
          </div>
          <SeverityBar counts={counts} className="h-3" />
          <div className="grid grid-cols-5 gap-2 text-center">
            {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
              <div key={sev} className="rounded-xl border border-border bg-popover/40 py-2">
                <p className="text-lg font-bold tabular-nums text-foreground">{counts[sev]}</p>
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{sev}</p>
              </div>
            ))}
          </div>
        </GlassPanel>
      </div>

      {s.status === "failed" && s.failure_reason && (
        <div className="mt-4">
          <ErrorBanner message={s.failure_reason} />
        </div>
      )}

      <Tabs defaultValue="findings" className="mt-8">
        <TabsList>
          <TabsTrigger value="findings">Findings ({findingList.length})</TabsTrigger>
          <TabsTrigger value="services">Serviços ({services.data?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="evidence">Evidências ({evidence.data?.count ?? 0})</TabsTrigger>
          <TabsTrigger value="authorization">Autorização</TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="mt-4">
          {findings.isLoading ? (
            <Skeleton className="h-32 w-full rounded-2xl" />
          ) : findingList.length === 0 ? (
            <EmptyState title="Nenhum finding" hint="Este scan não produziu findings." />
          ) : (
            <div className="glass overflow-x-auto p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Título</TableHead>
                    <TableHead>Severidade</TableHead>
                    <TableHead>CVSS</TableHead>
                    <TableHead>Categoria</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingList.map((f) => (
                    <TableRow
                      key={f.id}
                      className="cursor-pointer"
                      onClick={() => setSelected(f)}
                    >
                      <TableCell className="font-medium">{f.title}</TableCell>
                      <TableCell>
                        <SeverityBadge severity={f.severity} />
                      </TableCell>
                      <TableCell className="font-mono text-muted-foreground">
                        {f.cvss ?? "—"}
                      </TableCell>
                      <TableCell>
                        <CategoryBadge category={f.category} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        <TabsContent value="services" className="mt-4">
          {services.isLoading ? (
            <Skeleton className="h-32 w-full rounded-2xl" />
          ) : (services.data ?? []).length === 0 ? (
            <EmptyState title="Nenhum serviço" hint="Nenhum serviço foi descoberto por este scan." />
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
                  {services.data!.map((svc) => (
                    <TableRow key={svc.id}>
                      <TableCell className="font-mono text-primary">{svc.port}</TableCell>
                      <TableCell className="uppercase text-muted-foreground">
                        {svc.protocol}
                      </TableCell>
                      <TableCell>{svc.service_name}</TableCell>
                      <TableCell className="text-muted-foreground">{svc.product ?? "—"}</TableCell>
                      <TableCell className="font-mono text-muted-foreground">
                        {svc.version ?? "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        <TabsContent value="evidence" className="mt-4">
          {evidence.isLoading ? (
            <Skeleton className="h-32 w-full rounded-2xl" />
          ) : evidenceList.length === 0 ? (
            <EmptyState
              icon={Crosshair}
              title="Nenhuma exploração registrada"
              hint={
                s.status === "completed"
                  ? "Use “Explorar” para provar o impacto dos findings deste scan (requer autorização e o motor de exploração habilitado)."
                  : "A exploração roda sobre um scan concluído."
              }
              action={
                s.status === "completed" &&
                canWrite && (
                  <Button variant="secondary" disabled={exploit.isPending} onClick={onExploit}>
                    <Crosshair className="h-4 w-4" />
                    Explorar
                  </Button>
                )
              }
            />
          ) : (
            <div className="space-y-3">
              {evidenceList.map((ev) => (
                <GlassPanel key={ev.id} className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <EvidenceStatusBadge status={ev.status} />
                    {ev.impact_level !== "none" && <ImpactBadge impact={ev.impact_level} />}
                    <span className="min-w-0 truncate font-medium text-foreground">
                      {ev.finding?.title ?? ev.playbook_key}
                    </span>
                  </div>
                  {ev.proof && (
                    <pre className="thin-scroll max-h-40 overflow-auto whitespace-pre-wrap rounded-lg border border-destructive/30 bg-destructive/5 p-2 font-mono text-xs text-foreground/90">
                      {ev.proof}
                    </pre>
                  )}
                  {ev.steps_performed.length > 0 && <ExploitationTimeline steps={ev.steps_performed} />}
                  <Link
                    to="/evidence"
                    className="inline-block pt-1 text-xs text-primary hover:underline"
                  >
                    Ver na aba Evidências →
                  </Link>
                </GlassPanel>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="authorization" className="mt-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <GlassPanel>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Autorizado por</p>
              <p className="mt-1 font-medium text-foreground">{s.authorized_by}</p>
            </GlassPanel>
            <GlassPanel>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Tipo de scan</p>
              <p className="mt-1 font-medium capitalize text-foreground">{s.scan_type}</p>
            </GlassPanel>
            <GlassPanel className="sm:col-span-2">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">
                Escopo autorizado
              </p>
              <p className="mt-1 whitespace-pre-wrap font-mono text-sm text-primary">
                {s.authorization_scope}
              </p>
            </GlassPanel>
          </div>
        </TabsContent>
      </Tabs>

      <FindingDetailSheet finding={selected} onOpenChange={(open) => !open && setSelected(null)} />

      <ScanDeleteDialog
        scan={deleting ? s : null}
        onOpenChange={(open) => !open && setDeleting(false)}
        onDeleted={() => {
          toast.success("Scan excluído.");
          navigate("/scans");
        }}
      />

      <ConfirmDialog
        open={cancelling}
        onOpenChange={setCancelling}
        title="Cancelar scan"
        confirmLabel="Cancelar scan"
        cancelLabel="Voltar"
        variant="destructive"
        loading={cancel.isPending}
        onConfirm={() =>
          cancel.mutate(s.id, {
            onSuccess: () => {
              toast.success("Scan cancelado.");
              setCancelling(false);
            },
            onError: (err) => toast.error(errorMessage(err)),
          })
        }
      />
    </div>
  );
}
