/** Targets — cadastro de alvos com autorização (RF004, RN001/RN007). */

import { type FormEvent, useState } from "react";

import { PageHeader } from "../components/PageHeader";
import {
  Button,
  EmptyState,
  ErrorBanner,
  Field,
  GlassPanel,
  Input,
  Skeleton,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useCreateTarget, useTargets } from "../hooks/useData";
import { useAuthStore } from "../store/auth";

export function TargetsPage() {
  const role = useAuthStore((s) => s.user?.role);
  const canWrite = role === "analyst" || role === "admin";
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useTargets();
  const targets = data?.results ?? [];

  return (
    <div>
      <PageHeader
        title="Targets"
        description="Alvos autorizados. Toda varredura exige autorização documentada (RN007)."
        actions={
          canWrite && (
            <Button onClick={() => setOpen((v) => !v)} variant={open ? "ghost" : "primary"}>
              {open ? "Fechar" : "+ Novo alvo"}
            </Button>
          )
        }
      />

      {open && canWrite && <TargetForm onDone={() => setOpen(false)} />}

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : targets.length === 0 ? (
        <EmptyState title="Nenhum alvo cadastrado" hint="Cadastre um alvo autorizado para iniciar." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Nome</Th>
              <Th>Valor</Th>
              <Th>Tipo</Th>
              <Th>Autorizado por</Th>
              <Th>Escopo</Th>
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id} className="hover:bg-white/5">
                <Td className="font-medium">{t.name}</Td>
                <Td className="font-mono text-primary">{t.value}</Td>
                <Td className="uppercase text-muted">{t.kind}</Td>
                <Td className="text-muted">{t.authorized_by}</Td>
                <Td className="max-w-xs truncate text-muted">{t.authorization_scope}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}

function TargetForm({ onDone }: { onDone: () => void }) {
  const create = useCreateTarget();
  const [form, setForm] = useState({
    name: "",
    value: "",
    authorized_by: "",
    authorization_scope: "",
  });

  const set = (k: keyof typeof form) => (e: { target: { value: string } }) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate(form, { onSuccess: onDone });
  };

  return (
    <GlassPanel className="mb-6">
      <form onSubmit={onSubmit} className="grid gap-4 md:grid-cols-2">
        <Field label="Nome">
          <Input required value={form.name} onChange={set("name")} placeholder="DMZ empresa X" />
        </Field>
        <Field label="Valor (host / domínio / IP / CIDR)">
          <Input required value={form.value} onChange={set("value")} placeholder="192.168.10.0/24" />
        </Field>
        <Field label="Autorizado por">
          <Input required value={form.authorized_by} onChange={set("authorized_by")} placeholder="João Silva (CISO)" />
        </Field>
        <Field label="Escopo autorizado">
          <Input required value={form.authorization_scope} onChange={set("authorization_scope")} placeholder="192.168.10.0/24" />
        </Field>
        {create.isError && (
          <div className="md:col-span-2">
            <ErrorBanner message={(create.error as Error).message} />
          </div>
        )}
        <div className="md:col-span-2">
          <Button type="submit" disabled={create.isPending}>
            {create.isPending ? "Salvando…" : "Cadastrar alvo"}
          </Button>
        </div>
      </form>
    </GlassPanel>
  );
}
