/** Skeleton com a forma de uma tabela (linhas × colunas). */

import { Skeleton } from "@/components/ui/skeleton";

export function TableSkeleton({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className="glass overflow-hidden p-0">
      <div className="border-b border-border px-4 py-3">
        <Skeleton className="h-4 w-32" />
      </div>
      <div className="divide-y divide-border/60">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="flex items-center gap-4 px-4 py-3">
            {Array.from({ length: columns }).map((_, c) => (
              <Skeleton
                key={c}
                className="h-4"
                style={{ width: c === 0 ? "22%" : `${Math.max(10, 60 / columns)}%` }}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
