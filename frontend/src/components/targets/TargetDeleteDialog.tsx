/** Confirmação de exclusão de Target (admin — RN006). */

import { toast } from "sonner";

import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useDeleteTarget } from "@/hooks/useData";
import { errorMessage } from "@/lib/errors";
import type { Target } from "@/lib/types";

export function TargetDeleteDialog({
  target,
  onOpenChange,
  onDeleted,
}: {
  target: Target | null;
  onOpenChange: (open: boolean) => void;
  onDeleted: () => void;
}) {
  const del = useDeleteTarget();

  return (
    <ConfirmDialog
      open={Boolean(target)}
      onOpenChange={onOpenChange}
      title="Excluir alvo"
      variant="destructive"
      confirmLabel="Excluir alvo"
      loading={del.isPending}
      description={
        target && (
          <>
            <p>
              O alvo <span className="font-semibold text-foreground">{target.name}</span> (
              <span className="font-mono">{target.value}</span>) será removido permanentemente.
            </p>
            {target.scans_count > 0 && (
              <p>
                Este alvo tem{" "}
                <span className="font-semibold text-foreground">
                  {target.scans_count} scan{target.scans_count > 1 ? "s" : ""}
                </span>{" "}
                vinculado{target.scans_count > 1 ? "s" : ""}. O histórico será{" "}
                <span className="font-semibold text-foreground">preservado</span> — os scans apenas
                deixam de referenciar este alvo.
              </p>
            )}
          </>
        )
      }
      onConfirm={() => {
        if (!target) return;
        del.mutate(target.id, {
          onSuccess: onDeleted,
          onError: (err) => toast.error(errorMessage(err)),
        });
      }}
    />
  );
}
