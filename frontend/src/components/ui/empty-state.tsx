/** Estado vazio consistente (docs/ui.md) — ícone lucide + título + ação opcional. */

import type { ComponentType, ReactNode } from "react";

import { cn } from "@/lib/utils";

export function EmptyState({
  icon: Icon,
  title,
  hint,
  action,
  className,
}: {
  icon?: ComponentType<{ className?: string }>;
  title: string;
  hint?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "glass flex flex-col items-center justify-center gap-3 p-10 text-center",
        className,
      )}
    >
      {Icon && (
        <div className="rounded-2xl bg-primary/10 p-3 text-primary">
          <Icon className="h-6 w-6" />
        </div>
      )}
      <div className="space-y-1">
        <p className="font-semibold text-foreground">{title}</p>
        {hint && <p className="mx-auto max-w-md text-sm text-muted-foreground">{hint}</p>}
      </div>
      {action}
    </div>
  );
}
