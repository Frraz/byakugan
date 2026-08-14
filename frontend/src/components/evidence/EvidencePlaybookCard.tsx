/** Guia curado de exploração: PoC manual + escalação ("até onde dá para ir"). */

import { ArrowRight, ExternalLink, Wrench } from "lucide-react";

import type { ExploitationPlaybook } from "@/lib/types";
import { ImpactBadge, impactLabel } from "./ImpactBadge";

/** Interpola {url}/{param}/{host} de um comando de PoC com o contexto real. */
export function interpolate(
  template: string,
  ctx: { url?: string; param?: string; host?: string },
): string {
  return template
    .split("{url}")
    .join(ctx.url ?? "{url}")
    .split("{param}")
    .join(ctx.param ?? "{param}")
    .split("{host}")
    .join(ctx.host ?? "{host}");
}

export function EvidencePlaybookCard({
  playbook,
  context,
}: {
  playbook: ExploitationPlaybook;
  context?: { url?: string; param?: string; host?: string };
}) {
  const ctx = context ?? {};
  return (
    <div className="space-y-5 rounded-xl border border-accent/30 bg-accent/5 p-4">
      <div className="space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <p className="font-semibold text-foreground">{playbook.title}</p>
          <ImpactBadge impact={playbook.max_impact} />
        </div>
        <p className="text-sm text-foreground/90">{playbook.summary}</p>
        {playbook.prerequisites && (
          <p className="text-xs text-muted-foreground">
            <span className="font-medium">Pré-condição:</span> {playbook.prerequisites}
          </p>
        )}
      </div>

      {playbook.steps.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Passo a passo (prova de conceito)
          </h4>
          <ol className="space-y-2">
            {playbook.steps.map((step, i) => (
              <li key={i} className="rounded-lg border border-border bg-popover/50 p-2.5">
                <p className="text-sm font-medium text-foreground">
                  {i + 1}. {step.action}
                </p>
                {step.command && (
                  <pre className="thin-scroll mt-1 overflow-x-auto rounded bg-popover p-2 font-mono text-[11px] text-foreground/90">
                    {interpolate(step.command, ctx)}
                  </pre>
                )}
                {step.expected && (
                  <p className="mt-1 text-xs text-muted-foreground">→ {step.expected}</p>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}

      {playbook.escalation_path.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Até onde dá para ir (escalação)
          </h4>
          <ol className="space-y-1.5">
            {playbook.escalation_path.map((stage, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <ArrowRight className="mt-1 h-3.5 w-3.5 shrink-0 text-accent" />
                <span>
                  <span className="font-medium text-foreground">{stage.stage}</span>{" "}
                  <span className="text-[11px] text-muted-foreground">
                    ({impactLabel(stage.impact)})
                  </span>
                  <span className="block text-foreground/80">{stage.description}</span>
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {playbook.tools.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <Wrench className="h-3.5 w-3.5 text-muted-foreground" />
          {playbook.tools.map((tool) => (
            <span
              key={tool}
              className="rounded-md bg-secondary px-2 py-0.5 font-mono text-[11px] text-foreground/80"
            >
              {tool}
            </span>
          ))}
        </div>
      )}

      {playbook.references.length > 0 && (
        <ul className="space-y-1">
          {playbook.references.map((ref) => (
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
  );
}
