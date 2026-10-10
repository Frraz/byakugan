/** Base de conhecimento — leitura técnica editorial de remediação (RF0xx/RN013). */

import { useMemo, useState } from "react";
import { BookOpen, ExternalLink, Pencil, Plus, Search, Trash2 } from "lucide-react";

import { PageHeader } from "@/components/PageHeader";
import { KnowledgeArticleDeleteDialog } from "@/components/knowledge/KnowledgeArticleDeleteDialog";
import { KnowledgeArticleFormDialog } from "@/components/knowledge/KnowledgeArticleFormDialog";
import { CategoryBadge, CATEGORY_LABELS } from "@/components/ui/category-badge";
import { Button } from "@/components/ui/button";
import { DataPagination } from "@/components/ui/data-pagination";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { useGroupedFindings, useKnowledgeArticles } from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { usePageTitle } from "@/hooks/usePageTitle";
import { usePermissions } from "@/hooks/usePermissions";
import { errorMessage } from "@/lib/errors";
import { cn } from "@/lib/utils";
import type { FindingCategory, KnowledgeArticle } from "@/lib/types";
import { Link } from "react-router-dom";

function RelatedFindings({ category }: { category: string }) {
  const { data, isLoading } = useGroupedFindings({ category, page: 1 });
  const groups = data?.results ?? [];

  if (isLoading) return <Skeleton className="h-16 w-full" />;
  if (groups.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        Nenhum finding desta categoria registrado ainda nos scans executados.
      </p>
    );
  }
  return (
    <ul className="space-y-1.5">
      {groups.slice(0, 5).map((g) => (
        <li key={`${g.category}:${g.title}`}>
          <Link
            to="/vulnerabilities"
            className="flex items-center justify-between gap-2 rounded-lg border border-border bg-popover/50 p-2.5 text-sm hover:border-primary/40 hover:text-primary"
          >
            <span className="truncate">{g.title}</span>
            <span className="shrink-0 text-xs text-muted-foreground">
              {g.targets} {g.targets === 1 ? "alvo" : "alvos"}
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

function ArticleDetailSheet({
  article,
  onOpenChange,
  onEdit,
  onDelete,
}: {
  article: KnowledgeArticle | null;
  onOpenChange: (open: boolean) => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { canWrite, isAdmin } = usePermissions();
  return (
    <Sheet open={Boolean(article)} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="thin-scroll w-full overflow-y-auto sm:max-w-xl">
        {article && (
          <div className="space-y-6">
            <SheetHeader className="space-y-3 pr-10 text-left">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <CategoryBadge category={article.category} />
                {(canWrite || isAdmin) && (
                  <div className="flex items-center gap-1.5">
                    {canWrite && (
                      <Button variant="outline" size="sm" onClick={onEdit}>
                        <Pencil className="h-3.5 w-3.5" />
                        Editar
                      </Button>
                    )}
                    {isAdmin && (
                      <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" onClick={onDelete}>
                        <Trash2 className="h-3.5 w-3.5" />
                        Excluir
                      </Button>
                    )}
                  </div>
                )}
              </div>
              <SheetTitle className="text-lg leading-snug">{article.title}</SheetTitle>
              <SheetDescription className="sr-only">Artigo da base de conhecimento</SheetDescription>
            </SheetHeader>

            <section className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Resumo
              </h3>
              <p className="whitespace-pre-wrap text-sm text-foreground/90">{article.summary}</p>
            </section>

            <section className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Impacto
              </h3>
              <p className="whitespace-pre-wrap text-sm text-foreground/90">{article.impact}</p>
            </section>

            <section className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Remediação
              </h3>
              <ol className="list-decimal space-y-1.5 pl-5 text-sm text-foreground/90">
                {article.remediation_steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </section>

            {article.references.length > 0 && (
              <section className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Referências
                </h3>
                <ul className="space-y-1">
                  {article.references.map((ref) => (
                    <li key={ref}>
                      <a
                        href={ref}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 break-all text-xs text-primary hover:underline"
                      >
                        <ExternalLink className="h-3 w-3 shrink-0" />
                        {ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </section>
            )}

            <section className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Findings relacionados
              </h3>
              <RelatedFindings category={article.category} />
            </section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

export function KnowledgeBasePage() {
  usePageTitle("Base de conhecimento");
  const { canWrite } = usePermissions();

  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");
  const [page, setPage] = useState(1);
  const debounced = useDebounce(search);

  const [selected, setSelected] = useState<KnowledgeArticle | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<KnowledgeArticle | null>(null);
  const [deleting, setDeleting] = useState<KnowledgeArticle | null>(null);

  const params = useMemo(
    () => ({
      search: debounced || undefined,
      category: category === "all" ? undefined : category,
      page,
    }),
    [debounced, category, page],
  );
  const { data, isLoading, isError, error } = useKnowledgeArticles(params);
  const results = data?.results ?? [];

  const openCreate = () => {
    setEditing(null);
    setFormOpen(true);
  };
  const openEdit = (article: KnowledgeArticle) => {
    setSelected(null);
    setEditing(article);
    setFormOpen(true);
  };

  return (
    <div>
      <PageHeader
        title="Base de conhecimento"
        description="Remediação por categoria de vulnerabilidade — conteúdo de domínio editável, distinto do histórico imutável de scans e evidências."
        actions={
          canWrite && (
            <Button onClick={openCreate}>
              <Plus className="h-4 w-4" />
              Novo artigo
            </Button>
          )
        }
      />

      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Buscar por título ou resumo…"
            className="pl-9"
          />
        </div>
        <Select
          value={category}
          onValueChange={(v) => {
            setCategory(v);
            setPage(1);
          }}
        >
          <SelectTrigger className="w-full sm:w-56">
            <SelectValue placeholder="Categoria" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Todas as categorias</SelectItem>
            {(Object.keys(CATEGORY_LABELS) as FindingCategory[]).map((c) => (
              <SelectItem key={c} value={c}>
                {CATEGORY_LABELS[c]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <div className="grid gap-3 sm:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-28 w-full rounded-2xl" />
          ))}
        </div>
      ) : results.length === 0 ? (
        <EmptyState
          icon={BookOpen}
          title="Nenhum artigo encontrado"
          hint={
            search || category !== "all"
              ? "Ajuste os filtros para ver mais resultados."
              : "Artigos de remediação aparecem aqui conforme são cadastrados."
          }
          action={
            canWrite && (
              <Button onClick={openCreate}>
                <Plus className="h-4 w-4" />
                Novo artigo
              </Button>
            )
          }
        />
      ) : (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {results.map((article) => (
              <button
                key={article.id}
                onClick={() => setSelected(article)}
                className={cn(
                  "glass flex flex-col items-start gap-2 p-4 text-left transition-colors hover:border-primary/40",
                )}
              >
                <CategoryBadge category={article.category} />
                <p className="font-medium text-foreground">{article.title}</p>
                <p className="line-clamp-2 text-sm text-muted-foreground">{article.summary}</p>
              </button>
            ))}
          </div>
          <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
        </div>
      )}

      <ArticleDetailSheet
        article={selected}
        onOpenChange={(open) => !open && setSelected(null)}
        onEdit={() => selected && openEdit(selected)}
        onDelete={() => selected && setDeleting(selected)}
      />

      <KnowledgeArticleFormDialog open={formOpen} onOpenChange={setFormOpen} article={editing} />
      <KnowledgeArticleDeleteDialog
        article={deleting}
        onOpenChange={(open) => !open && setDeleting(null)}
        onDeleted={() => setDeleting(null)}
      />
    </div>
  );
}
