/** Diálogo de criação/edição de Target (RF004, RN001/RN007). */

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
import { useCreateTarget, useUpdateTarget, type TargetInput } from "@/hooks/useData";
import { errorMessage, fieldErrors } from "@/lib/errors";
import type { Target } from "@/lib/types";

const EMPTY: TargetInput = {
  name: "",
  value: "",
  authorized_by: "",
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
            authorized_by: target.authorized_by,
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
      ...form,
      authorization_expires_at: form.authorization_expires_at
        ? new Date(form.authorization_expires_at).toISOString()
        : null,
    };

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
            Toda varredura exige autorização documentada (RN007). O tipo é derivado do valor.
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
              placeholder="192.168.10.0/24"
            />
            {errors.value && <p className="text-xs text-destructive">{errors.value}</p>}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="t-auth">Autorizado por</Label>
            <Input
              id="t-auth"
              required
              value={form.authorized_by}
              onChange={(e) => set("authorized_by")(e.target.value)}
              placeholder="João Silva (CISO)"
            />
            {errors.authorized_by && (
              <p className="text-xs text-destructive">{errors.authorized_by}</p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="t-scope">Escopo autorizado</Label>
            <Input
              id="t-scope"
              required
              value={form.authorization_scope}
              onChange={(e) => set("authorization_scope")(e.target.value)}
              placeholder="192.168.10.0/24"
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
