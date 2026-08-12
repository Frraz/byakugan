/** Paginação para listas paginadas do backend (PAGE_SIZE=20). */

import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";

const PAGE_SIZE = 20;

export function DataPagination({
  count,
  page,
  onPageChange,
  pageSize = PAGE_SIZE,
}: {
  count: number;
  page: number;
  onPageChange: (page: number) => void;
  pageSize?: number;
}) {
  const totalPages = Math.max(1, Math.ceil(count / pageSize));
  if (count <= pageSize) return null;

  const from = (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, count);

  return (
    <div className="flex flex-col items-center justify-between gap-3 sm:flex-row">
      <p className="text-xs text-muted-foreground">
        Mostrando <span className="font-medium text-foreground">{from}</span>–
        <span className="font-medium text-foreground">{to}</span> de{" "}
        <span className="font-medium text-foreground">{count}</span>
      </p>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
        >
          <ChevronLeft className="h-4 w-4" />
          Anterior
        </Button>
        <span className="text-xs text-muted-foreground">
          Página {page} de {totalPages}
        </span>
        <Button
          variant="outline"
          size="sm"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
        >
          Próxima
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
