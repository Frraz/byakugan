/** Diálogo de criação de scan — via alvo cadastrado ou inline (RN001/RN002/RN007). */

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
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useCreateScan, useTargets } from "@/hooks/useData";
import { errorMessage } from "@/lib/errors";

const SCAN_TYPES = [
  { value: "discovery", label: "Discovery — descoberta de hosts/portas" },
  { value: "fingerprint", label: "Fingerprint — identificação de tecnologias" },
  { value: "vulnerability", label: "Vulnerability — correlação com CVEs" },
  { value: "full", label: "Full — varredura completa" },
];

export function ScanFormDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const create = useCreateScan();
  const { data: targetsData } = useTargets({ is_active: "true" });
  const targets = targetsData?.results ?? [];

  const [mode, setMode] = useState<"target" | "inline">("target");
  const [scanType, setScanType] = useState("discovery");
  const [targetRef, setTargetRef] = useState("");
  const [inline, setInline] = useState({ target: "", authorized_by: "", authorization_scope: "" });

  useEffect(() => {
    if (open) {
      setMode("target");
      setScanType("discovery");
      setTargetRef("");
      setInline({ target: "", authorized_by: "", authorization_scope: "" });
    }
  }, [open]);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const payload =
      mode === "target"
        ? { scan_type: scanType, target_ref: targetRef }
        : { scan_type: scanType, ...inline };
    create.mutate(payload, {
      onSuccess: () => {
        toast.success("Scan enfileirado.");
        onOpenChange(false);
      },
      onError: (err) => toast.error(errorMessage(err)),
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Novo scan</DialogTitle>
          <DialogDescription>
            A varredura só executa em alvos autorizados dentro do escopo (RN007).
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label>Tipo de scan</Label>
            <Select value={scanType} onValueChange={setScanType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SCAN_TYPES.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Tabs value={mode} onValueChange={(v) => setMode(v as "target" | "inline")}>
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="target">Alvo cadastrado</TabsTrigger>
              <TabsTrigger value="inline">Informar manualmente</TabsTrigger>
            </TabsList>
          </Tabs>

          {mode === "target" ? (
            <div className="space-y-1.5">
              <Label>Alvo autorizado</Label>
              <Select value={targetRef} onValueChange={setTargetRef}>
                <SelectTrigger>
                  <SelectValue placeholder="Selecione um alvo…" />
                </SelectTrigger>
                <SelectContent>
                  {targets.length === 0 ? (
                    <div className="px-2 py-3 text-center text-sm text-muted-foreground">
                      Nenhum alvo ativo cadastrado
                    </div>
                  ) : (
                    targets.map((t) => (
                      <SelectItem key={t.id} value={t.id}>
                        {t.name} — {t.value}
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="s-target">Alvo</Label>
                <Input
                  id="s-target"
                  required
                  className="font-mono"
                  value={inline.target}
                  onChange={(e) => setInline((f) => ({ ...f, target: e.target.value }))}
                  placeholder="empresa.com"
                />
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="s-auth">Autorizado por</Label>
                  <Input
                    id="s-auth"
                    required
                    value={inline.authorized_by}
                    onChange={(e) => setInline((f) => ({ ...f, authorized_by: e.target.value }))}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="s-scope">Escopo autorizado</Label>
                  <Input
                    id="s-scope"
                    required
                    value={inline.authorization_scope}
                    onChange={(e) =>
                      setInline((f) => ({ ...f, authorization_scope: e.target.value }))
                    }
                    placeholder="empresa.com"
                  />
                </div>
              </div>
            </div>
          )}

          {create.isError && <ErrorBanner message={errorMessage(create.error)} />}

          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancelar
            </Button>
            <Button
              type="submit"
              disabled={create.isPending || (mode === "target" && !targetRef)}
            >
              {create.isPending ? "Enfileirando…" : "Iniciar scan"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
