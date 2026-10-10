/** Diálogo de criação/edição de artigo da Knowledge Base (RN013 — write: analyst/admin). */

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { CATEGORY_LABELS } from "@/components/ui/category-badge";
import {
  useCreateKnowledgeArticle,
  useUpdateKnowledgeArticle,
  type CreateKnowledgeArticleInput,
} from "@/hooks/useData";
import { errorMessage, fieldErrors } from "@/lib/errors";
import type { FindingCategory, KnowledgeArticle } from "@/lib/types";

const EMPTY: CreateKnowledgeArticleInput = {
  slug: "",
  title: "",
  category: "",
  summary: "",
  impact: "",
  remediation_steps: [],
  references: [],
};

/** "Path Traversal em upload" → "path-traversal-em-upload". */
function slugify(title: string): string {
  return title
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function linesOf(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
}

export function KnowledgeArticleFormDialog({
  open,
  onOpenChange,
  article,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  article?: KnowledgeArticle | null;
}) {
  const isEdit = Boolean(article);
  const create = useCreateKnowledgeArticle();
  const update = useUpdateKnowledgeArticle();

  const [form, setForm] = useState<CreateKnowledgeArticleInput>(EMPTY);
  const [stepsText, setStepsText] = useState("");
  const [refsText, setRefsText] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!open) return;
    setErrors({});
    setSlugTouched(isEdit);
    if (article) {
      setForm({
        slug: article.slug,
        title: article.title,
        category: article.category,
        summary: article.summary,
        impact: article.impact,
        remediation_steps: article.remediation_steps,
        references: article.references,
      });
      setStepsText(article.remediation_steps.join("\n"));
      setRefsText(article.references.join("\n"));
    } else {
      setForm(EMPTY);
      setStepsText("");
      setRefsText("");
    }
  }, [open, article, isEdit]);

  const set = <K extends keyof CreateKnowledgeArticleInput>(k: K) => (value: CreateKnowledgeArticleInput[K]) =>
    setForm((f) => ({ ...f, [k]: value }));

  const onTitleChange = (title: string) => {
    set("title")(title);
    if (!slugTouched) set("slug")(slugify(title));
  };

  const steps = linesOf(stepsText);
  const refs = linesOf(refsText);
  const pending = create.isPending || update.isPending;
  const generalError = errors.detail || errors.non_field_errors;

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setErrors({});
    const payload: CreateKnowledgeArticleInput = {
      ...form,
      remediation_steps: steps,
      references: refs,
    };

    const onError = (err: unknown) => {
      setErrors(fieldErrors(err));
      toast.error(errorMessage(err));
    };
    const onSuccess = () => {
      toast.success(isEdit ? "Artigo atualizado." : "Artigo criado.");
      onOpenChange(false);
    };

    if (isEdit && article) update.mutate({ id: article.id, input: payload }, { onSuccess, onError });
    else create.mutate(payload, { onSuccess, onError });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="thin-scroll max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Editar artigo" : "Novo artigo"}</DialogTitle>
          <DialogDescription>
            Conteúdo de domínio editável — distinto do histórico imutável de scans/evidências/auditoria.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="kb-title">Título</Label>
              <Input
                id="kb-title"
                required
                value={form.title}
                onChange={(e) => onTitleChange(e.target.value)}
                placeholder="Path Traversal em upload de arquivos"
              />
              {errors.title && <p className="text-xs text-destructive">{errors.title}</p>}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="kb-category">Categoria</Label>
              <Select value={form.category} onValueChange={set("category")}>
                <SelectTrigger id="kb-category">
                  <SelectValue placeholder="Selecione…" />
                </SelectTrigger>
                <SelectContent>
                  {(Object.keys(CATEGORY_LABELS) as FindingCategory[]).map((c) => (
                    <SelectItem key={c} value={c}>
                      {CATEGORY_LABELS[c]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {errors.category && <p className="text-xs text-destructive">{errors.category}</p>}
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-slug">Slug</Label>
            <Input
              id="kb-slug"
              required
              className="font-mono"
              value={form.slug}
              onChange={(e) => {
                setSlugTouched(true);
                set("slug")(e.target.value);
              }}
            />
            {errors.slug && <p className="text-xs text-destructive">{errors.slug}</p>}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-summary">Resumo</Label>
            <Textarea
              id="kb-summary"
              required
              rows={2}
              value={form.summary}
              onChange={(e) => set("summary")(e.target.value)}
              placeholder="Explicação direta do que é a falha e por que importa."
            />
            {errors.summary && <p className="text-xs text-destructive">{errors.summary}</p>}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-impact">Impacto</Label>
            <Textarea
              id="kb-impact"
              required
              rows={2}
              value={form.impact}
              onChange={(e) => set("impact")(e.target.value)}
              placeholder="O que um atacante consegue fazer explorando isso."
            />
            {errors.impact && <p className="text-xs text-destructive">{errors.impact}</p>}
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="kb-steps">Remediação — um passo por linha</Label>
              <Textarea
                id="kb-steps"
                rows={5}
                value={stepsText}
                onChange={(e) => setStepsText(e.target.value)}
                placeholder={"Validar e normalizar o path recebido\nUsar allowlist de diretórios permitidos"}
              />
              {errors.remediation_steps && (
                <p className="text-xs text-destructive">{errors.remediation_steps}</p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Preview</Label>
              <div className="h-[8.5rem] overflow-y-auto rounded-md border border-border bg-popover/50 p-2.5">
                {steps.length === 0 ? (
                  <p className="text-xs text-muted-foreground">Nenhum passo ainda.</p>
                ) : (
                  <ol className="list-decimal space-y-1 pl-4 text-sm text-foreground/90">
                    {steps.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ol>
                )}
              </div>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="kb-refs">Referências — uma URL por linha (opcional)</Label>
              <Textarea
                id="kb-refs"
                rows={3}
                className="font-mono text-xs"
                value={refsText}
                onChange={(e) => setRefsText(e.target.value)}
                placeholder="https://owasp.org/..."
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Preview</Label>
              <div className="h-[5.25rem] overflow-y-auto rounded-md border border-border bg-popover/50 p-2.5">
                {refs.length === 0 ? (
                  <p className="text-xs text-muted-foreground">Nenhuma referência.</p>
                ) : (
                  <ul className="space-y-1">
                    {refs.map((r, i) => (
                      <li key={i} className="truncate break-all text-xs text-primary">
                        {r}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>

          {generalError && <ErrorBanner message={generalError} />}

          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancelar
            </Button>
            <Button type="submit" disabled={pending || steps.length === 0}>
              {pending ? "Salvando…" : isEdit ? "Salvar alterações" : "Criar artigo"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
