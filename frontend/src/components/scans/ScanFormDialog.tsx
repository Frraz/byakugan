/** Diálogo de criação de scan — via alvo cadastrado ou inline (RN001/RN002/RN007). */

import { type FormEvent, useEffect, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
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
import { cn } from "@/lib/utils";
import type { Intensity, PortSet } from "@/lib/types";

const SCAN_TYPES = [
  { value: "discovery", label: "Discovery — descoberta de hosts/portas" },
  { value: "fingerprint", label: "Fingerprint — identificação de tecnologias" },
  { value: "vulnerability", label: "Vulnerability — correlação com CVEs" },
  { value: "full", label: "Full — varredura completa" },
];

const INTENSITIES: { value: Intensity; label: string; hint: string }[] = [
  { value: "safe", label: "Safe", hint: "portas/wordlist reduzidas, sem credenciais/injeção" },
  { value: "normal", label: "Normal", hint: "perfil padrão recomendado" },
  { value: "aggressive", label: "Aggressive", hint: "credenciais default + injeção time-based" },
];

const PORT_SETS: { value: PortSet; label: string }[] = [
  { value: "top16", label: "Top 16 portas" },
  { value: "top100", label: "Top 100 portas" },
  { value: "top1000", label: "Top 1000 portas" },
];

/** Checks (adapters) disponíveis por scan_type — espelha ADAPTERS_BY_SCAN_TYPE no backend. */
const CHECKS_BY_SCAN_TYPE: Record<string, { name: string; label: string }[]> = {
  discovery: [
    { name: "dns", label: "DNS" },
    { name: "port-discovery", label: "Portas TCP" },
    { name: "udp-probe", label: "Serviços UDP" },
    { name: "subdomain-enum", label: "Enumeração de subdomínios" },
    { name: "zone-transfer", label: "Transferência de zona (AXFR)" },
    { name: "email-security", label: "Segurança de e-mail (SPF/DMARC/DKIM)" },
  ],
  fingerprint: [
    { name: "http-fingerprint", label: "Fingerprint HTTP" },
    { name: "tls", label: "TLS/Certificado" },
  ],
  vulnerability: [
    { name: "cve-lookup", label: "Correlação de CVEs" },
    { name: "default-creds", label: "Credenciais padrão" },
    { name: "web-scan", label: "Testes ativos web (injeção/exposição)" },
  ],
};
CHECKS_BY_SCAN_TYPE.full = [
  ...CHECKS_BY_SCAN_TYPE.discovery,
  ...CHECKS_BY_SCAN_TYPE.fingerprint,
  ...CHECKS_BY_SCAN_TYPE.vulnerability,
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

  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [intensity, setIntensity] = useState<Intensity>("normal");
  const [portSet, setPortSet] = useState<PortSet | "">("");
  const [wordlistSize, setWordlistSize] = useState("");
  const [excludedChecks, setExcludedChecks] = useState<Set<string>>(new Set());

  const availableChecks = CHECKS_BY_SCAN_TYPE[scanType] ?? [];

  useEffect(() => {
    if (open) {
      setMode("target");
      setScanType("discovery");
      setTargetRef("");
      setInline({ target: "", authorized_by: "", authorization_scope: "" });
      setAdvancedOpen(false);
      setIntensity("normal");
      setPortSet("");
      setWordlistSize("");
      setExcludedChecks(new Set());
    }
  }, [open]);

  // Trocar o tipo de scan muda o menu de checks disponíveis — reinicia a seleção.
  useEffect(() => {
    setExcludedChecks(new Set());
  }, [scanType]);

  const toggleCheck = (name: string) => {
    setExcludedChecks((cur) => {
      const next = new Set(cur);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();

    const options: Record<string, unknown> = { intensity };
    if (portSet) options.port_set = portSet;
    if (wordlistSize) options.wordlist_size = Number(wordlistSize);
    if (excludedChecks.size > 0) {
      options.enabled_checks = availableChecks
        .map((c) => c.name)
        .filter((name) => !excludedChecks.has(name));
    }

    const payload =
      mode === "target"
        ? { scan_type: scanType, target_ref: targetRef, options }
        : { scan_type: scanType, ...inline, options };
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

          <div className="space-y-1.5">
            <Label>Intensidade</Label>
            <Select value={intensity} onValueChange={(v) => setIntensity(v as Intensity)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {INTENSITIES.map((i) => (
                  <SelectItem key={i.value} value={i.value}>
                    {i.label} — {i.hint}
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

          <div className="rounded-xl border border-border">
            <button
              type="button"
              onClick={() => setAdvancedOpen((v) => !v)}
              className="flex w-full items-center gap-1.5 px-3 py-2 text-sm font-medium text-foreground"
            >
              {advancedOpen ? (
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              ) : (
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              )}
              Opções avançadas
            </button>
            {advancedOpen && (
              <div className="space-y-4 border-t border-border p-3">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>Conjunto de portas</Label>
                    <Select value={portSet} onValueChange={(v) => setPortSet(v as PortSet)}>
                      <SelectTrigger>
                        <SelectValue placeholder="Padrão do perfil" />
                      </SelectTrigger>
                      <SelectContent>
                        {PORT_SETS.map((p) => (
                          <SelectItem key={p.value} value={p.value}>
                            {p.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="s-wordlist">Wordlist de subdomínios</Label>
                    <Input
                      id="s-wordlist"
                      type="number"
                      min={1}
                      max={5000}
                      value={wordlistSize}
                      onChange={(e) => setWordlistSize(e.target.value)}
                      placeholder="Padrão do perfil"
                    />
                  </div>
                </div>

                {availableChecks.length > 0 && (
                  <div className="space-y-1.5">
                    <Label>Checks habilitados</Label>
                    <div className="flex flex-wrap gap-1.5">
                      {availableChecks.map((c) => {
                        const enabled = !excludedChecks.has(c.name);
                        return (
                          <button
                            key={c.name}
                            type="button"
                            onClick={() => toggleCheck(c.name)}
                            className={cn(
                              "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
                              enabled
                                ? "border-primary/50 bg-primary/10 text-primary"
                                : "border-border text-muted-foreground/60 line-through hover:text-muted-foreground",
                            )}
                          >
                            {c.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

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
