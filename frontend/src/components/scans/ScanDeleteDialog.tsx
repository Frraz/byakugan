/** Confirmação forte de exclusão de scan em cascata (admin — RN014). */

import { toast } from "sonner";

import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useDeleteScan } from "@/hooks/useData";
import { errorMessage } from "@/lib/errors";
import type { Scan } from "@/lib/types";

export function ScanDeleteDialog({
  scan,
  onOpenChange,
  onDeleted,
}: {
  scan: Scan | null;
  onOpenChange: (open: boolean) => void;
  onDeleted: () => void;
}) {
  const del = useDeleteScan();

  return (
    <ConfirmDialog
      open={Boolean(scan)}
      onOpenChange={onOpenChange}
      title="Excluir scan"
      variant="destructive"
      confirmLabel="Excluir permanentemente"
      loading={del.isPending}
      confirmText={scan?.target}
      description={
        scan && (
          <>
            <p>
              Esta ação é <span className="font-semibold text-foreground">irreversível</span>.
              Excluir este scan também remove:
            </p>
            <ul className="list-disc space-y-0.5 pl-5">
              <li>
                <span className="font-semibold text-foreground">
                  {scan.findings_count} finding{scan.findings_count === 1 ? "" : "s"}
                </span>{" "}
                associado{scan.findings_count === 1 ? "" : "s"};
              </li>
              <li>todos os relatórios gerados a partir dele (incluindo os arquivos);</li>
            </ul>
          </>
        )
      }
      onConfirm={() => {
        if (!scan) return;
        del.mutate(scan.id, {
          onSuccess: onDeleted,
          onError: (err) => toast.error(errorMessage(err)),
        });
      }}
    />
  );
}
