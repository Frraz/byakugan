/** KPI tile (docs/ui.md). Clicável quando `onClick` é fornecido. */

import type { ComponentType, ReactNode } from "react";

import { cn } from "@/lib/utils";

type Accent = "primary" | "danger" | "high" | "low" | "warning" | "success" | "accent" | "muted";

const ACCENTS: Record<Accent, { text: string; chip: string }> = {
  primary: { text: "text-primary", chip: "bg-primary/10 text-primary" },
  danger: { text: "text-destructive", chip: "bg-destructive/10 text-destructive" },
  high: { text: "text-sev-high", chip: "bg-sev-high/10 text-sev-high" },
  low: { text: "text-sev-low", chip: "bg-sev-low/10 text-sev-low" },
  warning: { text: "text-warning", chip: "bg-warning/10 text-warning" },
  success: { text: "text-success", chip: "bg-success/10 text-success" },
  accent: { text: "text-foreground", chip: "bg-secondary text-muted-foreground" },
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
  const Component = interactive ? "button" : "div";
  const a = ACCENTS[accent];
  return (
    <Component
      type={interactive ? "button" : undefined}
      onClick={onClick}
      aria-busy={loading}
      className={cn(
        "glass group flex min-w-0 items-center justify-between gap-3 p-4 text-left transition-colors duration-150",
        interactive &&
          "cursor-pointer hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        !interactive && "cursor-default",
      )}
    >
      <div className="min-w-0">
        <p className="text-xs font-medium text-muted-foreground">
          {label}
        </p>
        {loading ? (
          <div role="status" className="mt-1.5 h-7 w-16 animate-pulse rounded bg-secondary"><span className="sr-only">Carregando {label}</span></div>
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
    </Component>
  );
}
