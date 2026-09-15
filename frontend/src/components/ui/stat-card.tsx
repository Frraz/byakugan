/** KPI tile (docs/ui.md). Clicável quando `onClick` é fornecido. */

import type { ComponentType, ReactNode } from "react";

import { cn } from "@/lib/utils";

type Accent = "primary" | "danger" | "warning" | "success" | "accent" | "muted";

const ACCENTS: Record<Accent, { text: string; chip: string }> = {
  primary: { text: "text-primary", chip: "bg-primary/10 text-primary" },
  danger: { text: "text-destructive", chip: "bg-destructive/10 text-destructive" },
  warning: { text: "text-warning", chip: "bg-warning/10 text-warning" },
  success: { text: "text-success", chip: "bg-success/10 text-success" },
  accent: { text: "text-accent", chip: "bg-accent/10 text-accent" },
  muted: { text: "text-foreground", chip: "bg-secondary text-muted-foreground" },
};

export function StatCard({
  label,
  value,
  hint,
  accent = "primary",
  icon: Icon,
  onClick,
  loading = false,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  accent?: Accent;
  icon?: ComponentType<{ className?: string }>;
  onClick?: () => void;
  loading?: boolean;
}) {
  const interactive = Boolean(onClick);
  const a = ACCENTS[accent];
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!interactive}
      className={cn(
        "glass group flex items-center justify-between gap-3 p-4 text-left transition-all duration-200",
        interactive &&
          "cursor-pointer hover:-translate-y-0.5 hover:border-primary/40 hover:shadow-glow focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring motion-reduce:hover:translate-y-0",
        !interactive && "cursor-default",
      )}
    >
      <div className="min-w-0">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </p>
        {loading ? (
          <div className="mt-1.5 h-7 w-16 animate-pulse rounded bg-secondary" />
        ) : (
          <p className={cn("mt-1 text-2xl font-bold leading-none tabular-nums", a.text)}>{value}</p>
        )}
        {hint && !loading && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
      </div>
      {Icon && (
        <div
          className={cn(
            "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl transition-transform duration-200",
            a.chip,
            interactive && "group-hover:scale-110 motion-reduce:group-hover:scale-100",
          )}
        >
          <Icon className="h-5 w-5" />
        </div>
      )}
    </button>
  );
}
