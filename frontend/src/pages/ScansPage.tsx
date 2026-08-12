/** Scans — listar, criar (via target ou inline) e cancelar, com polling. */

import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";
import {
  Button,
  EmptyState,
  ErrorBanner,
  Field,
  GlassPanel,
  Input,
  Select,
  Skeleton,
  StatusBadge,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useCancelScan, useCreateScan, useScans, useTargets } from "../hooks/useData";
import { useAuthStore } from "../store/auth";

export function ScansPage() {
  const role = useAuthStore((s) => s.user?.role);
  const canWrite = role === "analyst" || role === "admin";
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useScans();
  const cancel = useCancelScan();
  const scans = data?.results ?? [];

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Descoberta autorizada de ativos e serviços."
        actions={
          canWrite && (
            <Button onClick={() => setOpen((v) => !v)} variant={open ? "ghost" : "primary"}>
              {open ? "Fechar" : "+ Novo scan"}
            </Button>
          )
        }
      />

      {open && canWrite && <ScanForm onDone={() => setOpen(false)} />}

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : scans.length === 0 ? (
        <EmptyState title="Nenhum scan" hint="Inicie uma descoberta a partir de um alvo autorizado." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Alvo</Th>
              <Th>Tipo</Th>
              <Th>Status</Th>
              <Th>Criado</Th>
              <Th />
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} className="hover:bg-white/5">
                <Td>
                  <Link to={`/scans/${s.id}`} className="font-medium text-primary hover:underline">
                    {s.target}
                  </Link>
                </Td>
                <Td className="capitalize text-muted">{s.scan_type}</Td>
                <Td>
                  <StatusBadge status={s.status} />
                </Td>
                <Td className="text-muted">{new Date(s.created_at).toLocaleString("pt-BR")}</Td>
                <Td className="text-right">
                  {canWrite && (s.status === "pending" || s.status === "running") && (
                    <Button variant="danger" onClick={() => cancel.mutate(s.id)}>
                      Cancelar
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}

function ScanForm({ onDone }: { onDone: () => void }) {
  const create = useCreateScan();
  const { data: targetsData } = useTargets();
  const targets = targetsData?.results ?? [];
  const [mode, setMode] = useState<"target" | "inline">("target");
  const [scanType, setScanType] = useState("discovery");
  const [targetRef, setTargetRef] = useState("");
  const [inline, setInline] = useState({ target: "", authorized_by: "", authorization_scope: "" });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const payload =
      mode === "target"
        ? { scan_type: scanType, target_ref: targetRef }
        : { scan_type: scanType, ...inline };
    create.mutate(payload, { onSuccess: onDone });
  };

  return (
    <GlassPanel className="mb-6">
      <form onSubmit={onSubmit} className="space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <Field label="Tipo de scan">
            <Select value={scanType} onChange={(e) => setScanType(e.target.value)}>
              <option value="discovery">Discovery</option>
              <option value="fingerprint">Fingerprint</option>
              <option value="full">Full</option>
            </Select>
          </Field>
          <Field label="Origem do alvo">
            <Select value={mode} onChange={(e) => setMode(e.target.value as "target" | "inline")}>
              <option value="target">Alvo cadastrado</option>
              <option value="inline">Informar manualmente</option>
            </Select>
          </Field>
        </div>

        {mode === "target" ? (
          <Field label="Alvo autorizado">
            <Select required value={targetRef} onChange={(e) => setTargetRef(e.target.value)}>
              <option value="">Selecione…</option>
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} — {t.value}
                </option>
              ))}
            </Select>
          </Field>
        ) : (
          <div className="grid gap-4 md:grid-cols-3">
            <Field label="Alvo">
              <Input required value={inline.target} onChange={(e) => setInline((f) => ({ ...f, target: e.target.value }))} placeholder="empresa.com" />
            </Field>
            <Field label="Autorizado por">
              <Input required value={inline.authorized_by} onChange={(e) => setInline((f) => ({ ...f, authorized_by: e.target.value }))} />
            </Field>
            <Field label="Escopo autorizado">
              <Input required value={inline.authorization_scope} onChange={(e) => setInline((f) => ({ ...f, authorization_scope: e.target.value }))} placeholder="empresa.com" />
            </Field>
          </div>
        )}

        {create.isError && <ErrorBanner message={(create.error as Error).message} />}

        <Button type="submit" disabled={create.isPending}>
          {create.isPending ? "Enfileirando…" : "Iniciar scan"}
        </Button>
      </form>
    </GlassPanel>
  );
}
