/** Confirmação de exclusão de artigo da Knowledge Base (admin). */

import { toast } from "sonner";

import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useDeleteKnowledgeArticle } from "@/hooks/useData";
import { errorMessage } from "@/lib/errors";
import type { KnowledgeArticle } from "@/lib/types";

export function KnowledgeArticleDeleteDialog({
  article,
  onOpenChange,
  onDeleted,
}: {
  article: KnowledgeArticle | null;
  onOpenChange: (open: boolean) => void;
  onDeleted: () => void;
}) {
  const del = useDeleteKnowledgeArticle();

  return (
    <ConfirmDialog
      open={Boolean(article)}
      onOpenChange={onOpenChange}
      title="Excluir artigo"
      variant="destructive"
      confirmLabel="Excluir artigo"
      loading={del.isPending}
      description={
        article && (
          <p>
            O artigo <span className="font-semibold text-foreground">{article.title}</span> será
            removido permanentemente. Isso não afeta findings já classificados nessa categoria —
            apenas remove o conteúdo de remediação associado.
          </p>
        )
      }
      onConfirm={() => {
        if (!article) return;
        del.mutate(article.id, {
          onSuccess: onDeleted,
          onError: (err) => toast.error(errorMessage(err)),
        });
      }}
    />
  );
}
