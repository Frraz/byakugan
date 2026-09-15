/** Diálogo de criação/edição de Target (RF004). Sistema privado: só nome + valor. */

import { type FormEvent, useEffect, useState } from "react";
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

const EMPTY: TargetInput = {
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
  const [form, setForm] = useState<TargetInput>(EMPTY);
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!open) return;
    setErrors({});
    setForm(
      target
        ? {
            name: target.name,
            value: target.value,
            authorization_scope: target.authorization_scope,
            authorization_expires_at: toLocalInput(target.authorization_expires_at),
            is_active: target.is_active,
          }
        : EMPTY,
    );
  }, [open, target]);

  const set = (k: keyof TargetInput) => (value: string | boolean) =>
    setForm((f) => ({ ...f, [k]: value }));

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setErrors({});
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
      setErrors(fieldErrors(err));
      toast.error(errorMessage(err));
    };
    const onSuccess = () => {
      toast.success(isEdit ? "Alvo atualizado." : "Alvo cadastrado.");
      onOpenChange(false);
    };

    if (isEdit && target) update.mutate({ id: target.id, input: payload }, { onSuccess, onError });
    else create.mutate(payload, { onSuccess, onError });
  };

  const pending = create.isPending || update.isPending;
  const generalError = errors.detail || errors.non_field_errors;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Editar alvo" : "Novo alvo"}</DialogTitle>
          <DialogDescription>
            Aceita host, domínio (ex.: byakugan.com.br), IPv4, IPv6 ou CIDR. O tipo é derivado
            automaticamente do valor.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="t-name">Nome</Label>
            <Input
              id="t-name"
              required
              value={form.name}
              onChange={(e) => set("name")(e.target.value)}
              placeholder="DMZ empresa X"
            />
            {errors.name && <p className="text-xs text-destructive">{errors.name}</p>}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="t-value">Valor (host / domínio / IP / CIDR)</Label>
            <Input
              id="t-value"
              required
              className="font-mono"
              value={form.value}
              onChange={(e) => set("value")(e.target.value)}
              placeholder="byakugan.com.br, 10.0.0.0/24 ou 2001:db8::1"
            />
            {errors.value && <p className="text-xs text-destructive">{errors.value}</p>}
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5">
              <Label htmlFor="t-scope">Escopo autorizado (opcional)</Label>
              <ScopeInfo />
            </div>
            <Input
              id="t-scope"
              className="font-mono"
              value={form.authorization_scope ?? ""}
              onChange={(e) => set("authorization_scope")(e.target.value)}
              placeholder="Vazio = usa o próprio alvo"
            />
            {errors.authorization_scope && (
              <p className="text-xs text-destructive">{errors.authorization_scope}</p>
            )}
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="t-expires">Autorização expira em (opcional)</Label>
              <Input
                id="t-expires"
                type="datetime-local"
                value={form.authorization_expires_at ?? ""}
                onChange={(e) => set("authorization_expires_at")(e.target.value)}
              />
            </div>
            {isEdit && (
              <div className="flex items-end gap-2 pb-2">
                <input
                  id="t-active"
                  type="checkbox"
                  checked={form.is_active}
                  onChange={(e) => set("is_active")(e.target.checked)}
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
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
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
