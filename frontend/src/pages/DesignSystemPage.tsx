/** Catálogo interno de desenvolvimento; excluído do roteamento de produção. */
import { useState } from "react";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { GlassPanel } from "@/components/ui/glass-panel";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ErrorBanner } from "@/components/ui/error-banner";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge, SEVERITY_ORDER } from "@/components/ui/severity-badge";
import { StatusBadge } from "@/components/ui/status-badge";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";

export function DesignSystemPage() {
  const [confirm, setConfirm] = useState(false);
  return <div className="space-y-6">
    <PageHeader title="Sistema visual" description="Catálogo interno de componentes e estados. Todas as amostras são demonstrativas, sem operações no backend." />
    <GlassPanel className="space-y-4"><h2 className="font-semibold">Ações e foco</h2><div className="flex flex-wrap gap-3">
      {(["default", "secondary", "outline", "ghost", "destructive", "link"] as const).map((variant) => <Button key={variant} variant={variant}>{variant}</Button>)}
      <Button disabled>Indisponível</Button><Button variant="outline" onClick={() => setConfirm(true)}>Confirmar ação de exemplo</Button>
    </div></GlassPanel>
    <GlassPanel className="space-y-4"><h2 className="font-semibold">Severidade e estado operacional</h2><div className="flex flex-wrap gap-3">{SEVERITY_ORDER.map((severity) => <SeverityBadge key={severity} severity={severity} />)}</div><div className="flex flex-wrap gap-3">{(["pending", "running", "completed", "failed", "cancelled"] as const).map((status) => <StatusBadge key={status} status={status} />)}</div></GlassPanel>
    <GlassPanel className="space-y-3"><h2 className="font-semibold">Campos e validação</h2><Label htmlFor="demo-host">Host de exemplo</Label><Input id="demo-host" placeholder="host.example.test" /><Label htmlFor="demo-error">Campo inválido</Label><Input id="demo-error" aria-invalid aria-describedby="demo-field-error" /><p id="demo-field-error" className="text-sm text-destructive">Mensagem de validação demonstrativa.</p></GlassPanel>
    <div className="grid min-w-0 gap-4 md:grid-cols-2"><EmptyState title="Nenhum registro de exemplo" hint="Descrição de como iniciar o fluxo." /><GlassPanel><h2 className="mb-3 font-semibold">Carregamento</h2><Skeleton className="h-24 w-full" /></GlassPanel></div>
    <ErrorBanner message="Erro de comunicação demonstrativo." onRetry={() => undefined} />
    <ConfirmDialog open={confirm} onOpenChange={setConfirm} title="Confirmar ação de exemplo" description="Demonstração do diálogo. Nenhum dado será alterado." onConfirm={() => setConfirm(false)} />
  </div>;
}
