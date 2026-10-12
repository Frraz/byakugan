/** Diálogo de criação/edição de Target (RF004). Sistema privado: só nome + valor. */

import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { targetFormSchema, type TargetFormValues } from "@/lib/forms";
import { FieldError } from "@/components/ui/field-error";
import { Info } from "lucide-react";
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
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useCreateTarget, useUpdateTarget, type TargetInput } from "@/hooks/useData";
import { errorMessage, fieldErrors } from "@/lib/errors";
import type { Target } from "@/lib/types";

const EMPTY: TargetFormValues = {
  name: "",
  value: "",
  authorization_scope: "",
  authorization_expires_at: "",
  is_active: true,
};

/** Converte ISO → valor de <input type="datetime-local"> (sem timezone). */
function toLocalInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Ícone (i) com explicação do que é o escopo autorizado e como usar. */
function ScopeInfo() {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label="O que é o escopo autorizado?"
          className="inline-flex h-4 w-4 items-center justify-center text-muted-foreground hover:text-foreground"
        >
          <Info className="h-4 w-4" />
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs text-left">
        <p className="text-xs leading-relaxed">
          Delimita <strong>exatamente</strong> o que o Byakugan pode tocar. Todo host testado —
          inclusive os expandidos de um CIDR — é revalidado contra este escopo antes de cada
          probe e de cada tentativa de exploração (fail-closed). Deixe vazio para usar o próprio
          valor do alvo como escopo. Ex.: <code>192.168.10.0/24</code> ou{" "}
          <code>byakugan.com.br</code>.
        </p>
      </TooltipContent>
    </Tooltip>
  );
}

export function TargetFormDialog({
  open,
  onOpenChange,
  target,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  target?: Target | null;
}) {
  const isEdit = Boolean(target);
  const create = useCreateTarget();
  const update = useUpdateTarget();
  const { register, reset, handleSubmit, setError, formState: { errors } } = useForm<TargetFormValues>({ resolver: zodResolver(targetFormSchema), defaultValues: EMPTY });

  useEffect(() => {
    if (!open) return;
    reset(
      target
        ? {
            name: target.name,
            value: target.value,
            authorization_scope: target.authorization_scope ?? "",
            authorization_expires_at: toLocalInput(target.authorization_expires_at),
            is_active: target.is_active,
          }
        : EMPTY,
    );
  }, [open, target, reset]);

  const pending = create.isPending || update.isPending;
  const onSubmit = (form: TargetFormValues) => {
    if (pending) return;
    const payload: TargetInput = {
      name: form.name,
      value: form.value,
      is_active: form.is_active,
      authorization_expires_at: form.authorization_expires_at
        ? new Date(form.authorization_expires_at).toISOString()
        : null,
    };
    // Só envia o escopo se preenchido — vazio deixa o backend usar o próprio alvo.
    if (form.authorization_scope?.trim()) {
      payload.authorization_scope = form.authorization_scope.trim();
    }

    const onError = (err: unknown) => {
      const fields = fieldErrors(err);
      for (const [field, message] of Object.entries(fields)) {
        if (field in EMPTY) setError(field as keyof TargetFormValues, { message });
      }
      setError("root", { message: errorMessage(err) });
      toast.error(errorMessage(err));
    };
    const onSuccess = () => {
      toast.success(isEdit ? "Alvo atualizado." : "Alvo cadastrado.");
      onOpenChange(false);
    };

    if (isEdit && target) update.mutate({ id: target.id, input: payload }, { onSuccess, onError });
    else create.mutate(payload, { onSuccess, onError });
  };

  const generalError = errors.root?.message;

  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Editar alvo" : "Novo alvo"}</DialogTitle>
          <DialogDescription>
            Aceita host, domínio (ex.: byakugan.com.br), IPv4, IPv6 ou CIDR. O tipo é derivado
            automaticamente do valor.
          </DialogDescription>
        </DialogHeader>

        <form noValidate onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="t-name">Nome</Label>
            <Input
              id="t-name"
              required
              {...register("name")}
              disabled={pending}
              aria-invalid={Boolean(errors.name)}
              aria-describedby="t-name-error"
              placeholder="DMZ empresa X"
            />
            <FieldError id="t-name-error" message={errors.name?.message} />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="t-value">Valor (host / domínio / IP / CIDR)</Label>
            <Input
              id="t-value"
              required
              className="font-mono"
              {...register("value")}
              disabled={pending}
              aria-invalid={Boolean(errors.value)}
              aria-describedby="t-value-error"
              placeholder="byakugan.com.br, 10.0.0.0/24 ou 2001:db8::1"
            />
            <FieldError id="t-value-error" message={errors.value?.message} />
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5">
              <Label htmlFor="t-scope">Escopo autorizado (opcional)</Label>
              <ScopeInfo />
            </div>
            <Input
              id="t-scope"
              className="font-mono"
              {...register("authorization_scope")}
              disabled={pending}
              aria-invalid={Boolean(errors.authorization_scope)}
              aria-describedby="t-authorization_scope-error"
              placeholder="Vazio = usa o próprio alvo"
            />
            <FieldError id="t-authorization_scope-error" message={errors.authorization_scope?.message} />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="t-expires">Autorização expira em (opcional)</Label>
              <Input
                id="t-expires"
                type="datetime-local"
                {...register("authorization_expires_at")}
                disabled={pending}
                aria-invalid={Boolean(errors.authorization_expires_at)}
                aria-describedby="t-authorization_expires_at-error"
              />
              <FieldError id="t-authorization_expires_at-error" message={errors.authorization_expires_at?.message} />
            </div>
            {isEdit && (
              <div className="flex items-end gap-2 pb-2">
                <input
                  id="t-active"
                  type="checkbox"
                  {...register("is_active")}
                  disabled={pending}
                  className="h-4 w-4 rounded border-input accent-primary"
                />
                <Label htmlFor="t-active" className="cursor-pointer">
                  Alvo ativo
                </Label>
              </div>
            )}
          </div>

          {generalError && <ErrorBanner message={generalError} />}

          <DialogFooter>
            <Button type="button" variant="ghost" disabled={pending} onClick={() => onOpenChange(false)}>
              Cancelar
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? "Salvando…" : isEdit ? "Salvar alterações" : "Cadastrar alvo"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
