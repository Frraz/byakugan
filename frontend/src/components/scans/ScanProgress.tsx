/** Barra de progresso do scan em execução — mostra fase corrente (adapter @ host). */

import { Progress } from "@/components/ui/progress";

export function ScanProgress({
  progress,
  phase,
  className,
}: {
  progress: number;
  phase: string;
  className?: string;
}) {
  return (
    <div className={className}>
      <div className="mb-1.5 flex items-center justify-between gap-2 text-xs text-muted-foreground">
        <span className="truncate">{phase || "Iniciando…"}</span>
        <span className="shrink-0 tabular-nums">{progress}%</span>
      </div>
      <Progress value={progress} />
    </div>
  );
}
