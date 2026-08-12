/** Heatmap categoria × severidade (grid custom com intensidade por contagem). */

import { SEVERITY_LABELS, SEVERITY_ORDER } from "@/components/ui/severity-badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import type { HeatmapCell, Severity } from "@/lib/types";

const CELL_BG: Record<Severity, string> = {
  critical: "bg-destructive",
  high: "bg-sev-high",
  medium: "bg-warning",
  low: "bg-primary",
  info: "bg-sev-info",
};

/** Opacidade proporcional (0.15–1) à intensidade da contagem na coluna. */
function intensity(count: number, max: number): number {
  if (count === 0) return 0;
  return 0.2 + 0.8 * (count / Math.max(max, 1));
}

export function CategoryHeatmap({ cells }: { cells: HeatmapCell[] }) {
  const categories = Array.from(new Set(cells.map((c) => c.category))).sort();
  const lookup = new Map(cells.map((c) => [`${c.category}|${c.severity}`, c.count]));
  const max = cells.reduce((m, c) => Math.max(m, c.count), 0);

  if (categories.length === 0) {
    return (
      <p className="py-6 text-center text-sm text-muted-foreground">
        Execute scans de vulnerability para popular a matriz de risco por categoria.
      </p>
    );
  }

  return (
    <div className="thin-scroll overflow-x-auto">
      <table className="w-full border-separate border-spacing-1 text-sm">
        <thead>
          <tr>
            <th className="p-2 text-left text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Categoria
            </th>
            {SEVERITY_ORDER.map((sev) => (
              <th
                key={sev}
                className="p-2 text-center text-xs font-semibold uppercase tracking-wide text-muted-foreground"
              >
                {SEVERITY_LABELS[sev]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {categories.map((category) => (
            <tr key={category}>
              <td className="p-2 font-medium capitalize text-foreground">{category}</td>
              {SEVERITY_ORDER.map((sev) => {
                const count = lookup.get(`${category}|${sev}`) ?? 0;
                return (
                  <td key={sev} className="p-0">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div
                          className={cn(
                            "relative flex h-10 items-center justify-center overflow-hidden rounded-md font-mono text-sm",
                            count > 0 ? "text-foreground" : "bg-secondary/40 text-muted-foreground/40",
                          )}
                        >
                          {count > 0 && (
                            <span
                              aria-hidden
                              className={cn("absolute inset-0 rounded-md", CELL_BG[sev])}
                              style={{ opacity: intensity(count, max) }}
                            />
                          )}
                          <span className="relative z-10">{count || "–"}</span>
                        </div>
                      </TooltipTrigger>
                      <TooltipContent>
                        {category} · {SEVERITY_LABELS[sev]}: {count}
                      </TooltipContent>
                    </Tooltip>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
