/** Diálogo de criação de scan — via alvo cadastrado ou inline (RN001/RN002/RN007). */

import { type FormEvent, useEffect, useState } from "react";
import { AlertTriangle, Check, Crosshair, Info, Radar, ShieldAlert } from "lucide-react";
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
import { DataPagination } from "@/components/ui/data-pagination";
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
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useCreateScan, useTargets } from "@/hooks/useData";
import { errorMessage } from "@/lib/errors";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";
import { targetValueSchema } from "@/lib/forms";
import { useDebounce } from "@/hooks/useDebounce";
import type { Intensity, PortSet, Target } from "@/lib/types";

const EXPIRING_SOON_DAYS = 7;

/** Status de autorização do alvo selecionado — mesma regra usada em TargetsPage. */
function targetAuthStatus(target: Target): { tone: "destructive" | "warning"; label: string } | null {
  if (!target.authorization_expires_at) return null;
  const msRemaining = new Date(target.authorization_expires_at).getTime() - Date.now();
  if (msRemaining < 0) {
    return { tone: "destructive", label: `Autorização expirada em ${formatDate(target.authorization_expires_at)}` };
  }
  if (msRemaining <= EXPIRING_SOON_DAYS * 24 * 60 * 60 * 1000) {
    return { tone: "warning", label: `Autorização vence em ${formatDate(target.authorization_expires_at)}` };
  }
  return null;
}

const SCAN_TYPES: { value: string; label: string; hint: string }[] = [
  { value: "discovery", label: "Discovery", hint: "Descoberta de hosts, portas, DNS e subdomínios" },
  { value: "fingerprint", label: "Fingerprint", hint: "Identificação de tecnologias, TLS e certificados" },
  { value: "vulnerability", label: "Vulnerability", hint: "Correlação de CVEs + testes ativos web" },
  { value: "full", label: "Full", hint: "Varredura completa (discovery + fingerprint + vuln)" },
];

const INTENSITIES: { value: Intensity; label: string; hint: string }[] = [
  { value: "safe", label: "Safe", hint: "Portas/wordlist reduzidas, sem credenciais/injeção" },
  { value: "normal", label: "Normal", hint: "Perfil padrão recomendado" },
  { value: "aggressive", label: "Aggressive", hint: "Credenciais default + injeção time-based" },
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

/** Cartão selecionável (radio-card) reutilizado por tipo de scan e intensidade. */
function OptionCard({
  active,
  title,
  hint,
  onClick,
}: {
  active: boolean;
  title: string;
  hint: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "relative flex flex-col items-start gap-0.5 rounded-xl border p-3 text-left transition-all duration-200",
        active
          ? "border-primary/60 bg-primary/10 shadow-glow"
          : "border-border hover:border-primary/30 hover:bg-secondary/50",
      )}
    >
      {active && (
        <span className="absolute right-2 top-2 flex h-4 w-4 items-center justify-center rounded-full bg-primary text-primary-foreground">
          <Check className="h-3 w-3" strokeWidth={3} />
        </span>
      )}
      <span className={cn("text-sm font-semibold", active ? "text-primary" : "text-foreground")}>
        {title}
      </span>
      <span className="pr-4 text-xs leading-snug text-muted-foreground">{hint}</span>
    </button>
  );
}

function SectionLabel({
  step,
  children,
  hint,
}: {
  step?: number;
  children: React.ReactNode;
  hint?: string;
}) {
  return (
    <div className="flex items-center gap-2">
      {step != null && (
        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/15 text-[11px] font-bold tabular-nums text-primary">
          {step}
        </span>
      )}
      <span
        className={cn(
          "text-sm font-semibold text-foreground",
          step == null && "text-xs uppercase tracking-wide text-muted-foreground",
        )}
      >
        {children}
      </span>
      {hint && (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              aria-label={hint}
              className="inline-flex h-4 w-4 items-center justify-center text-muted-foreground hover:text-foreground"
            >
              <Info className="h-4 w-4" />
            </button>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs text-left">
            <p className="text-xs leading-relaxed">{hint}</p>
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
}

export function ScanFormDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const create = useCreateScan();
  const resetCreate = create.reset;
  const [targetPage, setTargetPage] = useState(1);
  const [targetSearch, setTargetSearch] = useState("");
  const [validationError, setValidationError] = useState("");
  const debouncedTargetSearch = useDebounce(targetSearch);
  const { data: targetsData, isLoading: targetsLoading, isError: targetsFailed, error: targetsError, refetch: retryTargets } = useTargets({ is_active: "true", search: debouncedTargetSearch || undefined, page: targetPage }, open);
  const targets = targetsData?.results ?? [];

  const [mode, setMode] = useState<"target" | "inline">("target");
  const [scanType, setScanType] = useState("full");
  const [targetRef, setTargetRef] = useState("");
  const [inline, setInline] = useState({ target: "", authorization_scope: "" });

  const [intensity, setIntensity] = useState<Intensity>("normal");
  const [exploit, setExploit] = useState(false);
  const [portSet, setPortSet] = useState<PortSet | "">("");
  const [wordlistSize, setWordlistSize] = useState("");
  const [excludedChecks, setExcludedChecks] = useState<Set<string>>(new Set());

  const availableChecks = CHECKS_BY_SCAN_TYPE[scanType] ?? [];

  useEffect(() => {
    if (open) {
      resetCreate();
      setTargetPage(1);
      setTargetSearch("");
      setValidationError("");
      setMode("target");
      setScanType("full");
      setTargetRef("");
      setInline({ target: "", authorization_scope: "" });
      setIntensity("normal");
      setExploit(false);
      setPortSet("");
      setWordlistSize("");
      setExcludedChecks(new Set());
    }
  }, [open, resetCreate]);

  // Trocar o tipo de scan muda o menu de checks disponíveis — reinicia a seleção.
  useEffect(() => {
    setExcludedChecks(new Set());
  }, [scanType]);

  // A exploração só existe em aggressive — reseta ao sair desse perfil.
  useEffect(() => {
    if (intensity !== "aggressive") setExploit(false);
  }, [intensity]);

  const toggleCheck = (name: string) => {
    setExcludedChecks((cur) => {
      const next = new Set(cur);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const selectedTarget = targets.find((t) => t.id === targetRef);
  const targetLabel =
    mode === "target" ? selectedTarget?.value ?? "—" : inline.target || "—";
  const selectedTargetExpired =
    mode === "target" && selectedTarget != null && targetAuthStatus(selectedTarget)?.tone === "destructive";

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (create.isPending || selectedTargetExpired) return;
    setValidationError("");
    if (mode === "inline") {
      const parsed = targetValueSchema.safeParse(inline.target);
      if (!parsed.success) { setValidationError(parsed.error.issues[0].message); return; }
    } else if (!selectedTarget) { setValidationError("Selecione um alvo cadastrado."); return; }
    if (excludedChecks.size === availableChecks.length) { setValidationError("Habilite pelo menos um check para iniciar a análise."); return; }

    const options: Record<string, unknown> = { intensity };
    if (exploit && intensity === "aggressive") options.exploit = true;
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
        : {
            scan_type: scanType,
            target: inline.target.trim(),
            ...(inline.authorization_scope.trim()
              ? { authorization_scope: inline.authorization_scope.trim() }
              : {}),
            options,
          };
    create.mutate(payload, {
      onSuccess: () => {
        toast.success("Scan enfileirado.");
        onOpenChange(false);
      },
      onError: (err) => toast.error(errorMessage(err)),
    });
  };

  const scopeHint =
    "Delimita exatamente o que o Byakugan pode tocar. Todo host testado é revalidado contra este escopo antes de cada probe e de cada tentativa de exploração (fail-closed). Deixe vazio para usar o próprio alvo.";

  return (
    <Dialog open={open} onOpenChange={(next) => !create.isPending && onOpenChange(next)}>
      <DialogContent className="thin-scroll sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Novo scan</DialogTitle>
          <DialogDescription>
            A varredura só executa em alvos autorizados dentro do escopo (fail-closed).
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={onSubmit} className="space-y-6">
          <fieldset disabled={create.isPending} className="min-w-0 space-y-6">
          {/* 1 — Tipo de scan */}
          <section className="space-y-2">
            <SectionLabel step={1}>Tipo de scan</SectionLabel>
            <div className="grid gap-2 sm:grid-cols-2">
              {SCAN_TYPES.map((t) => (
                <OptionCard
                  key={t.value}
                  active={scanType === t.value}
                  title={t.label}
                  hint={t.hint}
                  onClick={() => setScanType(t.value)}
                />
              ))}
            </div>
          </section>

          {/* 2 — Alvo */}
          <section className="space-y-2">
            <SectionLabel step={2}>Alvo</SectionLabel>
            <Tabs value={mode} onValueChange={(v) => setMode(v as "target" | "inline")}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="target">Alvo cadastrado</TabsTrigger>
                <TabsTrigger value="inline">Informar manualmente</TabsTrigger>
              </TabsList>
            </Tabs>

            {mode === "target" ? (
              <div className="space-y-1.5">
                <Input aria-label="Buscar alvo cadastrado" placeholder="Buscar alvos…" value={targetSearch} onChange={(event) => { setTargetSearch(event.target.value); setTargetPage(1); setTargetRef(""); }} />
                {targetsLoading && <p role="status" className="text-sm text-muted-foreground">Carregando alvos…</p>}
                {targetsFailed && <ErrorBanner message={errorMessage(targetsError)} onRetry={() => void retryTargets()} />}
                <Select value={targetRef} onValueChange={setTargetRef}>
                  <SelectTrigger aria-label="Alvo cadastrado" disabled={targetsLoading || targetsFailed}>
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
                <DataPagination count={targetsData?.count ?? 0} page={targetPage} onPageChange={(page) => { setTargetPage(page); setTargetRef(""); }} />
                {selectedTarget && <dl className="space-y-1 rounded-md border border-border bg-muted p-3 text-sm"><dt className="text-muted-foreground">Escopo autorizado</dt><dd className="break-all font-mono">{selectedTarget.authorization_scope || "Escopo não informado"}</dd><dt className="text-muted-foreground">Validade</dt><dd>{selectedTarget.authorization_expires_at ? formatDate(selectedTarget.authorization_expires_at) : "Sem expiração informada"}</dd></dl>}
                {selectedTarget &&
                  (() => {
                    const status = targetAuthStatus(selectedTarget);
                    if (!status) return null;
                    return (
                      <p
                        className={cn(
                          "flex items-center gap-1.5 text-xs",
                          status.tone === "destructive" ? "text-destructive" : "text-warning",
                        )}
                      >
                        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                        {status.label}
                      </p>
                    );
                  })()}
              </div>
            ) : (
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <Label htmlFor="s-target">Alvo (host / domínio / IP / CIDR)</Label>
                  <Input
                    id="s-target"
                    required
                    className="font-mono"
                    value={inline.target}
                    onChange={(e) => setInline((f) => ({ ...f, target: e.target.value }))}
                    placeholder="byakugan.com.br, 10.0.0.0/24 ou 2001:db8::1"
                  />
                </div>
                <div className="space-y-1.5">
                  <SectionLabel hint={scopeHint}>Escopo autorizado (opcional)</SectionLabel>
                  <Input
                    id="s-scope"
                    aria-label="Escopo autorizado"
                    className="font-mono"
                    value={inline.authorization_scope}
                    onChange={(e) =>
                      setInline((f) => ({ ...f, authorization_scope: e.target.value }))
                    }
                    placeholder="Vazio = usa o próprio alvo"
                  />
                </div>
              </div>
            )}
          </section>

          {/* 3 — Intensidade */}
          <section className="space-y-2">
            <SectionLabel step={3}>Intensidade</SectionLabel>
            <div className="grid gap-2 sm:grid-cols-3">
              {INTENSITIES.map((i) => (
                <OptionCard
                  key={i.value}
                  active={intensity === i.value}
                  title={i.label}
                  hint={i.hint}
                  onClick={() => setIntensity(i.value)}
                />
              ))}
            </div>
          </section>

          {/* 4 — Exploração (prova de impacto) */}
          <section className="space-y-2">
            <SectionLabel step={4} hint="A exploração ativa prova o impacto real dos findings (ex.: extrair versão do banco via SQLi). É sempre não-destrutiva (RoE) e exige o motor de exploração habilitado. Só disponível em intensidade aggressive.">
              Exploração (prova de impacto)
            </SectionLabel>
            <button
              type="button"
              onClick={() => intensity === "aggressive" && setExploit((v) => !v)}
              disabled={intensity !== "aggressive"}
              aria-pressed={exploit}
              className={cn(
                "flex w-full items-start gap-3 rounded-xl border p-3 text-left transition-colors",
                intensity !== "aggressive"
                  ? "cursor-not-allowed border-border opacity-60"
                  : exploit
                    ? "border-destructive/50 bg-destructive/10"
                    : "border-border hover:border-destructive/30",
              )}
            >
              <span
                className={cn(
                  "mt-0.5 flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors",
                  exploit ? "justify-end bg-destructive" : "justify-start bg-secondary",
                )}
              >
                <span className="h-4 w-4 rounded-full bg-background" />
              </span>
              <span className="min-w-0">
                <span className="flex items-center gap-1.5 text-sm font-medium text-foreground">
                  <Crosshair className="h-4 w-4" />
                  Provar impacto explorando os findings
                </span>
                <span className="mt-0.5 block text-xs leading-snug text-muted-foreground">
                  {intensity === "aggressive"
                    ? "Não-destrutivo; escopo revalidado por finding. Requer o kill-switch de exploração ligado."
                    : "Disponível apenas em intensidade aggressive."}
                </span>
              </span>
            </button>
          </section>

          {/* 5 — Ajustes finos */}
          <section className="space-y-3">
            <SectionLabel step={5} hint="Padrões vêm do perfil de intensidade escolhido; limites máximos são impostos pelo backend.">
              Ajustes finos (opcional)
            </SectionLabel>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="s-ports">Conjunto de portas</Label>
                <Select value={portSet} onValueChange={(v) => setPortSet(v as PortSet)}>
                  <SelectTrigger id="s-ports">
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
                        aria-pressed={enabled}
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
          </section>

          {/* Resumo */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-xl border border-border bg-secondary/40 px-3 py-2 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1.5">
              <Radar className="h-3.5 w-3.5" /> {scanType}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5" /> {intensity}
            </span>
            {exploit && intensity === "aggressive" && (
              <span className="inline-flex items-center gap-1.5 text-destructive">
                <Crosshair className="h-3.5 w-3.5" /> exploração ligada
              </span>
            )}
            <span className="font-mono text-foreground/80">{targetLabel}</span>
          </div>

          {create.isError && <ErrorBanner message={errorMessage(create.error)} />}
          {validationError && <ErrorBanner message={validationError} />}
          <p className="text-sm text-muted-foreground">O servidor valida autorização, escopo e disponibilidade dos motores antes da execução. O envio não garante que o scan será iniciado.</p>

          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancelar
            </Button>
            <Button
              type="submit"
              disabled={
                create.isPending ||
                (mode === "target" && !targetRef) ||
                (mode === "inline" && !inline.target.trim()) ||
                selectedTargetExpired || excludedChecks.size === availableChecks.length
              }
            >
              {create.isPending
                ? "Enfileirando…"
                : selectedTargetExpired
                  ? "Autorização expirada"
                  : "Iniciar scan"}
            </Button>
          </DialogFooter>
          </fieldset>
        </form>
      </DialogContent>
    </Dialog>
  );
}
