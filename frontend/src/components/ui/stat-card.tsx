/** KPI tile (docs/ui.md). Clicável quando `onClick` é fornecido. */

import type { ComponentType, ReactNode } from "react";

import { cn } from "@/lib/utils";

type Accent = "primary" | "danger" | "warning" | "success" | "accent" | "muted";

const ACCENTS: Record<Accent, string> = {
  primary: "text-primary",
  danger: "text-destructive",
  warning: "text-warning",
  success: "text-success",
  accent: "text-accent",
  muted: "text-muted-foreground",
};

export function StatCard({
  label,
  value,
  hint,
  accent = "primary",
  icon: Icon,
  onClick,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  accent?: Accent;
  icon?: ComponentType<{ className?: string }>;
  onClick?: () => void;
}) {
  const interactive = Boolean(onClick);
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!interactive}
      className={cn(
        "glass flex items-center justify-between gap-3 p-4 text-left transition-colors",
        interactive && "cursor-pointer hover:border-primary/40 hover:bg-card focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        !interactive && "cursor-default",
      )}
    >
      <div className="min-w-0">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
        <p className={cn("mt-1 text-2xl font-bold tabular-nums", ACCENTS[accent])}>{value}</p>
        {hint && <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p>}
      </div>
      {Icon && (
        <div className={cn("shrink-0 rounded-xl bg-current/10 p-2", ACCENTS[accent])}>
          <Icon className="h-5 w-5" />
        </div>
      )}
    </button>
  );
}
