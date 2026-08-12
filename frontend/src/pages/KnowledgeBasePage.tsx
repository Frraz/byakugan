/** Knowledge Base — descrição, impacto e passos de remediação por categoria (RF014). */

import { type FormEvent, useMemo, useState } from "react";
import { BookOpen, ExternalLink, Plus, Search, Trash2 } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";

import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { DataPagination } from "@/components/ui/data-pagination";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import {
  useCreateKnowledgeArticle,
  useDeleteKnowledgeArticle,
  useKnowledgeArticles,
} from "@/hooks/useData";
import { useDebounce } from "@/hooks/useDebounce";
import { usePageTitle } from "@/hooks/usePageTitle";
import { usePermissions } from "@/hooks/usePermissions";
import { errorMessage } from "@/lib/errors";
import type { KnowledgeArticle } from "@/lib/types";

const linesToList = (text: string): string[] =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

export function KnowledgeBasePage() {
  usePageTitle("Knowledge Base");
  const { canWrite, isAdmin } = usePermissions();
  const [params, setParams] = useSearchParams();
  const category = params.get("category") ?? "";
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const debounced = useDebounce(search);

  const [formOpen, setFormOpen] = useState(false);
  const [deleting, setDeleting] = useState<KnowledgeArticle | null>(null);
  const del = useDeleteKnowledgeArticle();

  const query = useMemo(
    () => ({ category: category || undefined, search: debounced || undefined, page }),
    [category, debounced, page],
  );
  const { data, isLoading, isError, error } = useKnowledgeArticles(query);
  const articles = data?.results ?? [];

  return (
    <div>
      <PageHeader
        title="Knowledge Base"
        description="Descrição, impacto e passos de remediação por categoria de vulnerabilidade."
        actions={
          canWrite && (
            <Button onClick={() => setFormOpen(true)}>
              <Plus className="h-4 w-4" />
              Novo artigo
            </Button>
          )
        }
      />

      <div className="mb-6 flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="pl-9"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Buscar por título ou resumo…"
          />
        </div>
        {category && (
          <Button variant="outline" onClick={() => setParams({})}>
            Categoria: {category} ✕
          </Button>
        )}
      </div>

      {isError ? (
        <ErrorBanner message={errorMessage(error)} />
      ) : isLoading ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-48 w-full rounded-2xl" />
          <Skeleton className="h-48 w-full rounded-2xl" />
        </div>
      ) : articles.length === 0 ? (
        <EmptyState
          icon={BookOpen}
          title="Nenhum artigo encontrado"
          hint="Ajuste os filtros ou cadastre um novo artigo."
        />
      ) : (
        <div className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-2">
            {articles.map((a) => (
              <Card key={a.id} className="glass border-0">
                <CardHeader className="flex-row items-start justify-between gap-2 space-y-0">
                  <div className="space-y-2">
                    <Badge variant="secondary">{a.category}</Badge>
                    <CardTitle className="text-base">{a.title}</CardTitle>
                  </div>
                  {isAdmin && (
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label="Excluir artigo"
                      className="hover:text-destructive"
                      onClick={() => setDeleting(a)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <p className="text-muted-foreground">{a.summary}</p>
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground">Impacto</p>
                    <p className="mt-1 text-foreground/90">{a.impact}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-wide text-muted-foreground">
                      Passos de remediação
                    </p>
                    <ol className="mt-1 list-decimal space-y-1 pl-5 text-foreground/90">
                      {a.remediation_steps.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ol>
                  </div>
                  {a.references.length > 0 && (
                    <div>
                      <p className="text-xs uppercase tracking-wide text-muted-foreground">
                        Referências
                      </p>
                      <ul className="mt-1 space-y-1">
                        {a.references.map((url) => (
                          <li key={url}>
                            <a
                              href={url}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 break-all text-primary hover:underline"
                            >
                              <ExternalLink className="h-3 w-3 shrink-0" />
                              {url}
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
          <DataPagination count={data?.count ?? 0} page={page} onPageChange={setPage} />
        </div>
      )}

      <ArticleFormDialog open={formOpen} onOpenChange={setFormOpen} />
      <ConfirmDialog
        open={Boolean(deleting)}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Excluir artigo"
        variant="destructive"
        confirmLabel="Excluir"
        loading={del.isPending}
        description={deleting && <p>O artigo “{deleting.title}” será removido permanentemente.</p>}
        onConfirm={() => {
          if (!deleting) return;
          del.mutate(deleting.id, {
            onSuccess: () => {
              toast.success("Artigo excluído.");
              setDeleting(null);
            },
            onError: (err) => toast.error(errorMessage(err)),
          });
        }}
      />
    </div>
  );
}

function ArticleFormDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const create = useCreateKnowledgeArticle();
  const [form, setForm] = useState({ slug: "", title: "", category: "", summary: "", impact: "" });
  const [remediationText, setRemediationText] = useState("");
  const [referencesText, setReferencesText] = useState("");

  const reset = () => {
    setForm({ slug: "", title: "", category: "", summary: "", impact: "" });
    setRemediationText("");
    setReferencesText("");
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate(
      {
        ...form,
        remediation_steps: linesToList(remediationText),
        references: linesToList(referencesText),
      },
      {
        onSuccess: () => {
          toast.success("Artigo salvo.");
          reset();
          onOpenChange(false);
        },
        onError: (err) => toast.error(errorMessage(err)),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="thin-scroll max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Novo artigo</DialogTitle>
          <DialogDescription>
            Todo artigo precisa de resumo, impacto e ao menos um passo de remediação (RN013).
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor="kb-slug">Slug</Label>
              <Input
                id="kb-slug"
                required
                value={form.slug}
                onChange={(e) => setForm((f) => ({ ...f, slug: e.target.value }))}
                placeholder="weak-tls"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="kb-title">Título</Label>
              <Input
                id="kb-title"
                required
                value={form.title}
                onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="kb-category">Categoria</Label>
              <Input
                id="kb-category"
                required
                value={form.category}
                onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))}
                placeholder="tls, web, network…"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-summary">Resumo</Label>
            <Textarea
              id="kb-summary"
              required
              rows={2}
              value={form.summary}
              onChange={(e) => setForm((f) => ({ ...f, summary: e.target.value }))}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-impact">Impacto</Label>
            <Textarea
              id="kb-impact"
              required
              rows={2}
              value={form.impact}
              onChange={(e) => setForm((f) => ({ ...f, impact: e.target.value }))}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-remediation">Passos de remediação (um por linha)</Label>
            <Textarea
              id="kb-remediation"
              required
              rows={4}
              value={remediationText}
              onChange={(e) => setRemediationText(e.target.value)}
              placeholder={"Atualize o software…\nRestrinja o acesso…"}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-refs">Referências (uma URL por linha, opcional)</Label>
            <Textarea
              id="kb-refs"
              rows={2}
              value={referencesText}
              onChange={(e) => setReferencesText(e.target.value)}
            />
          </div>

          {create.isError && <ErrorBanner message={errorMessage(create.error)} />}

          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancelar
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? "Salvando…" : "Salvar artigo"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
