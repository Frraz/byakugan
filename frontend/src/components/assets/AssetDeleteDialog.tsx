/** Confirmação forte de exclusão de ativo em cascata (admin — RN006/RN020). */

import { toast } from "sonner";

import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useDeleteAsset } from "@/hooks/useData";
import { errorMessage } from "@/lib/errors";
import type { Asset } from "@/lib/types";

export function assetLabel(asset: Asset): string {
  return asset.hostname || asset.ip || asset.domain || asset.id.slice(0, 8);
}

export function AssetDeleteDialog({
  asset,
  onOpenChange,
  onDeleted,
}: {
  asset: Asset | null;
  onOpenChange: (open: boolean) => void;
  onDeleted: () => void;
}) {
  const del = useDeleteAsset();

  return (
    <ConfirmDialog
      open={Boolean(asset)}
      onOpenChange={onOpenChange}
      title="Excluir ativo"
      variant="destructive"
      confirmLabel="Excluir permanentemente"
      loading={del.isPending}
      confirmText={asset ? assetLabel(asset) : undefined}
      description={
        asset && (
          <>
            <p>
              Esta ação é <span className="font-semibold text-foreground">irreversível</span>. Excluir
              o ativo <span className="font-mono text-foreground">{assetLabel(asset)}</span> também
              remove:
            </p>
            <ul className="list-disc space-y-0.5 pl-5">
              <li>
                <span className="font-semibold text-foreground">
                  {asset.findings_count} finding{asset.findings_count === 1 ? "" : "s"}
                </span>{" "}
                associado{asset.findings_count === 1 ? "" : "s"};
              </li>
              <li>serviços, tecnologias e registros DNS descobertos para ele.</li>
            </ul>
          </>
        )
      }
      onConfirm={() => {
        if (!asset) return;
        del.mutate(asset.id, {
          onSuccess: onDeleted,
          onError: (err) => toast.error(errorMessage(err)),
        });
      }}
    />
  );
}
