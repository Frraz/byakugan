/** Badge de status de scan (docs/ui.md). */

import type { ScanStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

const STYLES: Record<ScanStatus, string> = {
  pending: "bg-sev-info/15 text-sev-info border-sev-info/40",
  running: "bg-primary/15 text-primary border-primary/40",
  completed: "bg-success/15 text-success border-success/40",
  failed: "bg-destructive/15 text-destructive border-destructive/40",
  cancelled: "bg-warning/15 text-warning border-warning/40",
};

const LABELS: Record<ScanStatus, string> = {
  pending: "Pendente",
  running: "Executando",
  completed: "Concluído",
  failed: "Falhou",
  cancelled: "Cancelado",
};

export function StatusBadge({ status, className }: { status: ScanStatus; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        STYLES[status],
        className,
      )}
      aria-label={`Status ${LABELS[status]}`}
    >
      <span
        className={cn("h-1.5 w-1.5 rounded-full bg-current", status === "running" && "animate-pulse")}
        aria-hidden
      />
      {LABELS[status]}
    </span>
  );
}

export const SCAN_STATUS_LABELS = LABELS;
