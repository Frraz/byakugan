/** Evidências — resultados de exploração automatizada + playbooks de exploração (Fase 7+). */

import { useMemo, useState } from "react";
import { Crosshair, Search, ShieldAlert } from "lucide-react";

import { PageHeader } from "@/components/PageHeader";
import { EvidencePlaybookCard } from "@/components/evidence/EvidencePlaybookCard";
import { ExploitationTimeline } from "@/components/evidence/ExploitationTimeline";
import { EvidenceStatusBadge, ImpactBadge } from "@/components/evidence/ImpactBadge";
import { CategoryBadge } from "@/components/ui/category-badge";
import { DataPagination } from "@/components/ui/data-pagination";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/ui/severity-badge";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useEvidence, usePlaybook, usePlaybooks } from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { usePageTitle } from "@/hooks/usePageTitle";
import { errorMessage } from "@/lib/errors";
import { formatDateTime, formatRelative } from "@/lib/format";
import type { Evidence } from "@/lib/types";

function assetLabel(evidence: Evidence): string {
  const a = evidence.asset;
  if (!a) return "—";
  return a.hostname || a.ip || a.domain || a.id.slice(0, 8);
}

/** Extrai (url, param, host) da evidência do finding para interpolar o playbook. */
function contextFor(evidence: Evidence): { url?: string; param?: string; host?: string } {
  const host = evidence.asset?.hostname || evidence.asset?.ip || evidence.asset?.domain || undefined;
  return { host };
}

function EvidenceDetailSheet({
  evidence,
  onOpenChange,
}: {
  evidence: Evidence | null;
  onOpenChange: (open: boolean) => void;
}) {
  const { data: playbook } = usePlaybook(evidence?.playbook_key || null);

  return (
    <Sheet open={Boolean(evidence)} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="thin-scroll w-full overflow-y-auto sm:max-w-2xl">
        {evidence && (
          <div className="space-y-6">
            <SheetHeader className="space-y-3 text-left">
              <div className="flex flex-wrap items-center gap-2">
                <EvidenceStatusBadge status={evidence.status} />
                {evidence.impact_level !== "none" && <ImpactBadge impact={evidence.impact_level} />}
                {evidence.finding && <SeverityBadge severity={evidence.finding.severity} />}
                {evidence.finding && <CategoryBadge category={evidence.finding.category} />}
              </div>
              <SheetTitle className="text-lg leading-snug">
                {evidence.finding?.title ?? evidence.playbook_key}
              </SheetTitle>
              <SheetDescription className="sr-only">Detalhe da evidência</SheetDescription>
            </SheetHeader>

            {evidence.proof && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Prova extraída
                </h3>
                <pre className="thin-scroll max-h-56 overflow-auto whitespace-pre-wrap rounded-xl border border-destructive/30 bg-destructive/5 p-3 font-mono text-xs text-foreground/90">
                  {evidence.proof}
                </pre>
              </section>
            )}

            <section className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                O que o Byakugan executou (até onde foi)
              </h3>
              <ExploitationTimeline steps={evidence.steps_performed} />
            </section>

            {evidence.chain.length > 0 && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Encadeamento
                </h3>
                <ul className="space-y-1.5">
                  {evidence.chain.map((link, i) => (
                    <li key={i} className="rounded-lg border border-border bg-popover/50 p-2 text-sm">
                      <span className="font-medium text-foreground">{link.finding}</span> —{" "}
                      {link.description}
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {playbook && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Guia de exploração (manual)
                </h3>
                <EvidencePlaybookCard playbook={playbook} context={contextFor(evidence)} />
              </section>
            )}

            <p className="text-xs text-muted-foreground">
              Executado em {formatDateTime(evidence.created_at)} · RoE: {evidence.roe_profile || "—"}
            </p>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

function EvidenceTab() {
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Evidence | null>(null);
  const params = useMemo(() => ({ status: "proven", page }), [page]);
  const { data, isLoading, isError, error } = useEvidence(params);
  const results = data?.results ?? [];

  if (isError) return <ErrorBanner message={errorMessage(error)} />;
  if (isLoading) return <TableSkeleton columns={4} />;
  if (results.length === 0) {
    return (
      <EmptyState
        icon={Crosshair}
        title="Nenhuma exploração comprovada ainda"
        hint="Rode um scan aggressive com exploração habilitada (opt-in) ou dispare a exploração num scan concluído. Requer BYAKUGAN_EXPLOITATION_ENABLED e autorização no escopo."
      />
    );
  }

  return (
    <div className="space-y-3">
      {results.map((ev) => (
        <button
          key={ev.id}
          onClick={() => setSelected(ev)}
          className="glass w-full space-y-2 p-4 text-left transition-colors hover:border-primary/40"
        >
          <div className="flex flex-wrap items-center gap-2">
            <EvidenceStatusBadge status={ev.status} />
            {ev.impact_level !== "none" && <ImpactBadge impact={ev.impact_level} />}
            <span className="ml-auto text-xs text-muted-foreground">{formatRelative(ev.created_at)}</span>
          </div>
          <p className="font-medium text-foreground">{ev.finding?.title ?? ev.playbook_key}</p>
          {ev.proof && (
            <p className="line-clamp-2 font-mono text-xs text-muted-foreground">{ev.proof}</p>
          )}
          <p className="text-xs text-muted-foreground">Ativo: {assetLabel(ev)}</p>
        </button>
      ))}
      <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
      <EvidenceDetailSheet evidence={selected} onOpenChange={(open) => !open && setSelected(null)} />
    </div>
  );
}

function PlaybooksTab() {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const debounced = useDebounce(search);
  const params = useMemo(() => ({ search: debounced || undefined, page }), [debounced, page]);
  const { data, isLoading, isError, error } = usePlaybooks(params);
  const results = data?.results ?? [];

  return (
    <div className="space-y-4">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          placeholder="Buscar por classe de vulnerabilidade…"
          className="pl-9"
        />
      </div>

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <TableSkeleton columns={3} />
      ) : results.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="Nenhum playbook encontrado"
          hint="Os playbooks de exploração são semeados por classe de vulnerabilidade (SQLi, XSS, SSRF, credencial default…)."
        />
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-2">
            {results.map((pb) => (
              <EvidencePlaybookCard key={pb.id} playbook={pb} />
            ))}
          </div>
          <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
        </>
      )}
    </div>
  );
}

export function EvidencePage() {
  usePageTitle("Evidências");
  return (
    <div>
      <PageHeader
        title="Evidências"
        description="Prova de exploração automatizada (o que o Byakugan comprovou) e guias de exploração por vulnerabilidade — como explorar e até onde dá para ir."
      />
      <Tabs defaultValue="evidence">
        <TabsList>
          <TabsTrigger value="evidence">Exploração comprovada</TabsTrigger>
          <TabsTrigger value="playbooks">Playbooks</TabsTrigger>
        </TabsList>
        <TabsContent value="evidence" className="mt-4">
          <EvidenceTab />
        </TabsContent>
        <TabsContent value="playbooks" className="mt-4">
          <PlaybooksTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
