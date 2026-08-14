/** Badge do impacto comprovado por uma exploração (aba Evidências). */

import { cn } from "@/lib/utils";
import type { EvidenceStatus, ImpactLevel } from "@/lib/types";

const IMPACT_LABELS: Record<ImpactLevel, string> = {
  rce: "RCE",
  "db-read": "Leitura de banco",
  "file-read": "Leitura de arquivos",
  "auth-bypass": "Bypass de autenticação",
  ssrf: "Acesso interno (SSRF)",
  "info-disclosure": "Vazamento de informação",
  session: "Roubo de sessão",
  none: "Sem impacto",
};

/** Cores por severidade do impacto — RCE/db-read/auth-bypass são os mais graves. */
const IMPACT_STYLES: Record<ImpactLevel, string> = {
  rce: "bg-destructive/15 text-destructive border-destructive/40",
  "db-read": "bg-destructive/15 text-destructive border-destructive/40",
  "auth-bypass": "bg-destructive/15 text-destructive border-destructive/40",
  "file-read": "bg-sev-high/15 text-sev-high border-sev-high/40",
  ssrf: "bg-sev-high/15 text-sev-high border-sev-high/40",
  "info-disclosure": "bg-warning/15 text-warning border-warning/40",
  session: "bg-sev-high/15 text-sev-high border-sev-high/40",
  none: "bg-secondary text-muted-foreground border-border",
};

export function ImpactBadge({ impact, className }: { impact: ImpactLevel; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        IMPACT_STYLES[impact] ?? IMPACT_STYLES.none,
        className,
      )}
    >
      {IMPACT_LABELS[impact] ?? impact}
    </span>
  );
}

export function impactLabel(impact: ImpactLevel | string): string {
  return IMPACT_LABELS[impact as ImpactLevel] ?? String(impact);
}

const STATUS_LABELS: Record<EvidenceStatus, string> = {
  proven: "Comprovado",
  attempted: "Tentado",
  failed: "Falhou",
  blocked: "Bloqueado (RoE)",
  "not-attempted": "Não tentado",
};

const STATUS_STYLES: Record<EvidenceStatus, string> = {
  proven: "bg-destructive/15 text-destructive border-destructive/40",
  attempted: "bg-sev-info/15 text-sev-info border-sev-info/40",
  failed: "bg-secondary text-muted-foreground border-border",
  blocked: "bg-warning/15 text-warning border-warning/40",
  "not-attempted": "bg-secondary text-muted-foreground border-border",
};

export function EvidenceStatusBadge({ status }: { status: EvidenceStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        STATUS_STYLES[status] ?? STATUS_STYLES.failed,
      )}
    >
      {STATUS_LABELS[status] ?? status}
    </span>
  );
}
