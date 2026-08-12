/** Knowledge Base — descrição, impacto e passos de remediação por categoria (RF014). */

import { type FormEvent, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";
import {
  Button,
  EmptyState,
  ErrorBanner,
  Field,
  GlassPanel,
  Input,
  Skeleton,
  Textarea,
} from "../components/ui";
import {
  useCreateKnowledgeArticle,
  useDeleteKnowledgeArticle,
  useKnowledgeArticles,
} from "../hooks/useData";
import { useAuthStore } from "../store/auth";

const linesToList = (text: string): string[] =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

export function KnowledgeBasePage() {
  const role = useAuthStore((s) => s.user?.role);
  const canWrite = role === "analyst" || role === "admin";
  const isAdmin = role === "admin";
  const [open, setOpen] = useState(false);
  const [params, setParams] = useSearchParams();
  const category = params.get("category") ?? "";
  const [search, setSearch] = useState("");

  const { data, isLoading, isError } = useKnowledgeArticles({
    category: category || undefined,
    search: search || undefined,
  });
  const deleteArticle = useDeleteKnowledgeArticle();
  const articles = data?.results ?? [];

  return (
    <div>
      <PageHeader
        title="Knowledge Base"
        description="Descrição, impacto e passos de remediação por categoria de vulnerabilidade."
        actions={
          canWrite && (
            <Button onClick={() => setOpen((v) => !v)} variant={open ? "ghost" : "primary"}>
              {open ? "Fechar" : "+ Novo artigo"}
            </Button>
          )
        }
      />

      <div className="mb-6 flex flex-wrap items-end gap-3">
        <Field label="Buscar">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="título, resumo…"
          />
        </Field>
        <Field label="Categoria">
          <Input
            value={category}
            onChange={(e) => setParams(e.target.value ? { category: e.target.value } : {})}
            placeholder="software, tls, web…"
          />
        </Field>
      </div>

      {open && canWrite && <ArticleForm onDone={() => setOpen(false)} />}

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : isError ? (
        <ErrorBanner message="Não foi possível carregar a Knowledge Base." />
      ) : articles.length === 0 ? (
        <EmptyState
          title="Nenhum artigo encontrado"
          hint="Ajuste os filtros ou cadastre um novo artigo."
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {articles.map((a) => (
            <GlassPanel key={a.id}>
              <div className="flex items-start justify-between gap-2">
                <div>
                  <span className="inline-block rounded-full border border-primary/40 bg-primary/10 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide text-primary">
                    {a.category}
                  </span>
                  <h3 className="mt-2 text-base font-semibold text-foreground">{a.title}</h3>
                </div>
                {isAdmin && (
                  <Button variant="danger" onClick={() => deleteArticle.mutate(a.id)}>
                    Excluir
                  </Button>
                )}
              </div>

              <p className="mt-3 text-sm text-muted">{a.summary}</p>

              <p className="mt-3 text-xs uppercase tracking-wide text-muted">Impacto</p>
              <p className="mt-1 text-sm text-foreground">{a.impact}</p>

              <p className="mt-3 text-xs uppercase tracking-wide text-muted">Passos de remediação</p>
              <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm text-foreground">
                {a.remediation_steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>

              {a.references.length > 0 && (
                <>
                  <p className="mt-3 text-xs uppercase tracking-wide text-muted">Referências</p>
                  <ul className="mt-1 space-y-1 text-sm">
                    {a.references.map((url) => (
                      <li key={url}>
                        <a
                          href={url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-primary hover:underline"
                        >
                          {url}
                        </a>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </GlassPanel>
          ))}
        </div>
      )}
    </div>
  );
}

function ArticleForm({ onDone }: { onDone: () => void }) {
  const create = useCreateKnowledgeArticle();
  const [form, setForm] = useState({
    slug: "",
    title: "",
    category: "",
    summary: "",
    impact: "",
  });
  const [remediationText, setRemediationText] = useState("");
  const [referencesText, setReferencesText] = useState("");

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate(
      {
        ...form,
        remediation_steps: linesToList(remediationText),
        references: linesToList(referencesText),
      },
      { onSuccess: onDone },
    );
  };

  return (
    <GlassPanel className="mb-6">
      <form onSubmit={onSubmit} className="space-y-4">
        <div className="grid gap-4 md:grid-cols-3">
          <Field label="Slug">
            <Input
              required
              value={form.slug}
              onChange={(e) => setForm((f) => ({ ...f, slug: e.target.value }))}
              placeholder="weak-tls"
            />
          </Field>
          <Field label="Título">
            <Input
              required
              value={form.title}
              onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
            />
          </Field>
          <Field label="Categoria">
            <Input
              required
              value={form.category}
              onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))}
              placeholder="tls, web, network…"
            />
          </Field>
        </div>

        <Field label="Resumo">
          <Textarea
            required
            rows={2}
            value={form.summary}
            onChange={(e) => setForm((f) => ({ ...f, summary: e.target.value }))}
          />
        </Field>

        <Field label="Impacto">
          <Textarea
            required
            rows={2}
            value={form.impact}
            onChange={(e) => setForm((f) => ({ ...f, impact: e.target.value }))}
          />
        </Field>

        <Field label="Passos de remediação (um por linha)">
          <Textarea
            required
            rows={4}
            value={remediationText}
            onChange={(e) => setRemediationText(e.target.value)}
            placeholder={"Atualize o software...\nRestrinja o acesso..."}
          />
        </Field>

        <Field label="Referências (uma URL por linha, opcional)">
          <Textarea
            rows={2}
            value={referencesText}
            onChange={(e) => setReferencesText(e.target.value)}
          />
        </Field>

        {create.isError && <ErrorBanner message={(create.error as Error).message} />}

        <Button type="submit" disabled={create.isPending}>
          {create.isPending ? "Salvando…" : "Salvar artigo"}
        </Button>
      </form>
    </GlassPanel>
  );
}
