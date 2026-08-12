/** Painel lateral com o detalhe completo de um finding (RN008 + Knowledge Base). */

import { Boxes, ExternalLink, Radar } from "lucide-react";
import { Link } from "react-router-dom";

import { SeverityBadge } from "@/components/ui/severity-badge";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { useKnowledgeArticles } from "@/hooks/useData";
import { formatDateTime } from "@/lib/format";
import type { Finding } from "@/lib/types";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </h3>
      {children}
    </section>
  );
}

function assetLabel(finding: Finding): string {
  const a = finding.asset;
  if (!a) return "—";
  return a.hostname || a.ip || a.domain || a.id.slice(0, 8);
}

export function FindingDetailSheet({
  finding,
  onOpenChange,
}: {
  finding: Finding | null;
  onOpenChange: (open: boolean) => void;
}) {
  const category = finding?.category;
  const { data: kb } = useKnowledgeArticles(category ? { category } : undefined);
  const article = kb?.results?.[0];
  const vuln = finding?.vulnerability;

  return (
    <Sheet open={Boolean(finding)} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="thin-scroll w-full overflow-y-auto sm:max-w-xl"
      >
        {finding && (
          <div className="space-y-6">
            <SheetHeader className="space-y-3 text-left">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                {finding.cvss != null && (
                  <span className="rounded-md bg-secondary px-2 py-0.5 font-mono text-xs">
                    CVSS {finding.cvss}
                  </span>
                )}
                <span className="rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground">
                  {finding.category}
                </span>
              </div>
              <SheetTitle className="text-lg leading-snug">{finding.title}</SheetTitle>
              <SheetDescription className="sr-only">Detalhe do finding</SheetDescription>
            </SheetHeader>

            <Section title="Descrição">
              <p className="whitespace-pre-wrap text-sm text-foreground/90">{finding.description}</p>
            </Section>

            {finding.evidence && (
              <Section title="Evidência">
                <pre className="thin-scroll max-h-64 overflow-auto rounded-xl border border-border bg-popover p-3 font-mono text-xs text-foreground/90">
                  {finding.evidence}
                </pre>
              </Section>
            )}

            <Section title="Recomendação">
              <p className="whitespace-pre-wrap text-sm text-foreground/90">
                {finding.recommendation}
              </p>
            </Section>

            {vuln && (
              <Section title="Vulnerabilidade (catálogo)">
                <div className="space-y-2 rounded-xl border border-border bg-popover/50 p-3">
                  {vuln.cve && (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 font-mono text-sm font-semibold text-primary hover:underline"
                    >
                      {vuln.cve}
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                  )}
                  <p className="text-sm text-foreground/90">{vuln.title}</p>
                  {vuln.cvss_vector && (
                    <p className="font-mono text-xs text-muted-foreground">{vuln.cvss_vector}</p>
                  )}
                  {vuln.references.length > 0 && (
                    <ul className="space-y-1 pt-1">
                      {vuln.references.map((ref) => (
                        <li key={ref}>
                          <a
                            href={ref}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 break-all text-xs text-primary hover:underline"
                          >
                            <ExternalLink className="h-3 w-3 shrink-0" />
                            {ref}
                          </a>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </Section>
            )}

            {article && (
              <Section title="Remediação (Knowledge Base)">
                <div className="space-y-2 rounded-xl border border-accent/30 bg-accent/5 p-3">
                  <p className="font-semibold text-foreground">{article.title}</p>
                  <p className="text-sm text-foreground/90">{article.summary}</p>
                  {article.remediation_steps.length > 0 && (
                    <ol className="list-decimal space-y-1 pl-4 text-sm text-foreground/90">
                      {article.remediation_steps.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ol>
                  )}
                  <Link
                    to={`/knowledge?category=${encodeURIComponent(finding.category)}`}
                    className="inline-block pt-1 text-xs text-primary hover:underline"
                  >
                    Ver na Knowledge Base →
                  </Link>
                </div>
              </Section>
            )}

            <Section title="Contexto">
              <div className="flex flex-wrap gap-2">
                {finding.asset && (
                  <Link
                    to={`/assets/${finding.asset.id}`}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm hover:border-primary/40 hover:text-primary"
                  >
                    <Boxes className="h-4 w-4" />
                    {assetLabel(finding)}
                  </Link>
                )}
                {finding.scan && (
                  <Link
                    to={`/scans/${finding.scan.id}`}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm hover:border-primary/40 hover:text-primary"
                  >
                    <Radar className="h-4 w-4" />
                    {finding.scan.target}
                  </Link>
                )}
              </div>
              <p className="pt-2 text-xs text-muted-foreground">
                Detectado em {formatDateTime(finding.created_at)}
              </p>
            </Section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
