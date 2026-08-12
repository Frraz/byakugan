/** Mini-indicadores de contagem de findings por severidade. */

import type { SeverityCounts } from "@/lib/types";
import { cn } from "@/lib/utils";
import { SEVERITY_LABELS, SEVERITY_ORDER } from "./severity-badge";

const DOT: Record<keyof SeverityCounts, string> = {
  critical: "bg-destructive text-destructive",
  high: "bg-sev-high text-sev-high",
  medium: "bg-warning text-warning",
  low: "bg-primary text-primary",
  info: "bg-sev-info text-sev-info",
};

/** Pills compactos por severidade (só severidades com contagem > 0). */
export function SeveritySummary({
  counts,
  className,
}: {
  counts: SeverityCounts;
  className?: string;
}) {
  const active = SEVERITY_ORDER.filter((s) => counts[s] > 0);
  if (active.length === 0) {
    return <span className="text-sm text-muted-foreground">—</span>;
  }
  return (
    <div className={cn("flex flex-wrap items-center gap-1.5", className)}>
      {active.map((s) => (
        <span
          key={s}
          className={cn(
            "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-semibold tabular-nums",
            "bg-current/10",
            DOT[s].split(" ")[1],
          )}
          title={`${SEVERITY_LABELS[s]}: ${counts[s]}`}
        >
          <span className={cn("h-1.5 w-1.5 rounded-full", DOT[s].split(" ")[0])} />
          {counts[s]}
        </span>
      ))}
    </div>
  );
}

/** Barra empilhada proporcional por severidade. */
export function SeverityBar({ counts, className }: { counts: SeverityCounts; className?: string }) {
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + counts[s], 0);
  if (total === 0) {
    return <div className={cn("h-2 w-full rounded-full bg-secondary", className)} />;
  }
  return (
    <div className={cn("flex h-2 w-full overflow-hidden rounded-full bg-secondary", className)}>
      {SEVERITY_ORDER.map((s) =>
        counts[s] > 0 ? (
          <div
            key={s}
            className={DOT[s].split(" ")[0]}
            style={{ width: `${(counts[s] / total) * 100}%` }}
            title={`${SEVERITY_LABELS[s]}: ${counts[s]}`}
          />
        ) : null,
      )}
    </div>
  );
}
