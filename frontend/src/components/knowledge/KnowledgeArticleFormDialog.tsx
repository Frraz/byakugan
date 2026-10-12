/** Diálogo de criação/edição de artigo da Knowledge Base (RN013 — write: analyst/admin). */

import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { knowledgeFormSchema } from "@/lib/forms";
import { FieldError } from "@/components/ui/field-error";
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

type Values = z.infer<typeof knowledgeFormSchema>;
const EMPTY: Values = { slug: "", title: "", category: "", summary: "", impact: "", stepsText: "", refsText: "" };

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

  const { register, watch, reset, setValue, setError, handleSubmit, formState: { errors: formErrors } } = useForm<Values>({ resolver: zodResolver(knowledgeFormSchema), defaultValues: EMPTY });
  const form = watch();
  const stepsText = form.stepsText;
  const refsText = form.refsText;
  const errors = Object.fromEntries(Object.entries(formErrors).map(([key, error]) => [key, error?.message ?? ""]));
  const [slugTouched, setSlugTouched] = useState(false);

  useEffect(() => {
    if (!open) return;
    setSlugTouched(isEdit);
    reset(article ? { slug: article.slug, title: article.title, category: article.category, summary: article.summary, impact: article.impact, stepsText: article.remediation_steps.join("\n"), refsText: article.references.join("\n") } : EMPTY);
  }, [open, article, isEdit, reset]);

  const set = (key: keyof Values) => (value: string) => setValue(key, value, { shouldValidate: Boolean(formErrors[key]) });

  const onTitleChange = (title: string) => {
    set("title")(title);
    if (!slugTouched) set("slug")(slugify(title));
  };

  const steps = linesOf(stepsText);
  const refs = linesOf(refsText);
  const pending = create.isPending || update.isPending;
  const generalError = formErrors.root?.message;

  const onSubmit = (values: Values) => {
    if (pending) return;
    const payload: CreateKnowledgeArticleInput = {
      slug: values.slug, title: values.title, category: values.category, summary: values.summary, impact: values.impact,
      remediation_steps: linesOf(values.stepsText),
      references: linesOf(values.refsText),
    };

    const onError = (err: unknown) => {
      for (const [field, message] of Object.entries(fieldErrors(err))) {
        const key = field === "remediation_steps" ? "stepsText" : field === "references" ? "refsText" : field;
        if (key in EMPTY) setError(key as keyof Values, { message });
      }
      setError("root", { message: errorMessage(err) });
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
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent className="thin-scroll max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Editar artigo" : "Novo artigo"}</DialogTitle>
          <DialogDescription>
            Conteúdo de domínio editável — distinto do histórico imutável de scans/evidências/auditoria.
          </DialogDescription>
        </DialogHeader>

        <form noValidate onSubmit={handleSubmit(onSubmit)} className="space-y-4"><fieldset disabled={pending} className="min-w-0 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="kb-title">Título</Label>
              <Input
                id="kb-title"
                {...register("title")}
                aria-invalid={Boolean(errors.title)} aria-describedby="kb-title-error"
                required
                value={form.title}
                onChange={(e) => onTitleChange(e.target.value)}
                placeholder="Path Traversal em upload de arquivos"
              />
              <FieldError id="kb-title-error" message={errors.title} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="kb-category">Categoria</Label>
              <Select value={form.category} onValueChange={set("category")}>
                <SelectTrigger id="kb-category" disabled={pending} aria-invalid={Boolean(errors.category)} aria-describedby="kb-category-error">
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
              <FieldError id="kb-category-error" message={errors.category} />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-slug">Slug</Label>
            <Input
              id="kb-slug"
                {...register("slug")}
                aria-invalid={Boolean(errors.slug)} aria-describedby="kb-slug-error"
              required
              className="font-mono"
              value={form.slug}
              onChange={(e) => {
                setSlugTouched(true);
                set("slug")(e.target.value);
              }}
            />
            <FieldError id="kb-slug-error" message={errors.slug} />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-summary">Resumo</Label>
            <Textarea
              id="kb-summary"
                {...register("summary")}
                aria-invalid={Boolean(errors.summary)} aria-describedby="kb-summary-error"
              required
              rows={2}
              value={form.summary}
              onChange={(e) => set("summary")(e.target.value)}
              placeholder="Explicação direta do que é a falha e por que importa."
            />
            <FieldError id="kb-summary-error" message={errors.summary} />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="kb-impact">Impacto</Label>
            <Textarea
              id="kb-impact"
                {...register("impact")}
                aria-invalid={Boolean(errors.impact)} aria-describedby="kb-impact-error"
              required
              rows={2}
              value={form.impact}
              onChange={(e) => set("impact")(e.target.value)}
              placeholder="O que um atacante consegue fazer explorando isso."
            />
            <FieldError id="kb-impact-error" message={errors.impact} />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="kb-steps">Remediação — um passo por linha</Label>
              <Textarea
                id="kb-steps" {...register("stepsText")} aria-invalid={Boolean(errors.stepsText)} aria-describedby="kb-steps-error"
                rows={5}
                value={stepsText}
                onChange={(e) => setValue("stepsText", e.target.value)}
                placeholder={"Validar e normalizar o path recebido\nUsar allowlist de diretórios permitidos"}
              />
              <FieldError id="kb-steps-error" message={errors.stepsText} />
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
                id="kb-refs" {...register("refsText")} aria-invalid={Boolean(errors.refsText)} aria-describedby="kb-refs-error"
                rows={3}
                className="font-mono text-xs"
                value={refsText}
                onChange={(e) => setValue("refsText", e.target.value)}
                placeholder="https://owasp.org/..."
              /><FieldError id="kb-refs-error" message={errors.refsText} />
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
            <Button type="submit" disabled={pending}>
              {pending ? "Salvando…" : isEdit ? "Salvar alterações" : "Criar artigo"}
            </Button>
          </DialogFooter>
          </fieldset></form>
      </DialogContent>
    </Dialog>
  );
}
