/** Badge de severidade (cor + texto + ponto — acessibilidade, docs/ui.md). */

import type { Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

const STYLES: Record<Severity, string> = {
  critical: "bg-destructive/15 text-destructive border-destructive/40",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-warning/15 text-warning border-warning/40",
  low: "bg-primary/15 text-primary border-primary/40",
  info: "bg-sev-info/15 text-sev-info border-sev-info/40",
};

const LABELS: Record<Severity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Média",
  low: "Baixa",
  info: "Info",
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        STYLES[severity],
        className,
      )}
      aria-label={`Severidade ${LABELS[severity]}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {LABELS[severity]}
    </span>
  );
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
export const SEVERITY_LABELS = LABELS;
