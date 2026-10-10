/**
 * Matriz de cobertura OWASP Top 10 (2021 + 2025) de um scan — diferencia
 * testada / encontrada / provada, e marca cobertura limitada como limitação
 * explícita (nunca "segura") — PLANO_REDESIGN_BYAKUGAN.md §5.8.
 */

import { AlertTriangle, Check, Crosshair, Minus } from "lucide-react";

import { SeverityBadge } from "@/components/ui/severity-badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { OwaspCoverage, OwaspCoverageRow, OwaspEdition, OwaspEditionSummary } from "@/lib/types";

function SummaryPill({
  label,
  value,
  total,
  tone,
}: {
  label: string;
  value: number;
  total: number;
  tone: "primary" | "warning" | "destructive" | "muted";
}) {
  const toneClass = {
    primary: "border-primary/40 bg-primary/10 text-primary",
    warning: "border-warning/40 bg-warning/10 text-warning",
    destructive: "border-destructive/40 bg-destructive/10 text-destructive",
    muted: "border-border text-muted-foreground",
  }[tone];
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium", toneClass)}>
      {label}
      <span className="font-mono tabular-nums">
        {value}/{total}
      </span>
    </span>
  );
}

function EditionSummaryBar({ summary }: { summary: OwaspEditionSummary }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <SummaryPill label="Testadas" value={summary.tested} total={summary.total} tone="primary" />
      <SummaryPill label="Encontradas" value={summary.found} total={summary.total} tone="warning" />
      <SummaryPill label="Provadas" value={summary.proven} total={summary.total} tone="destructive" />
      {summary.limited > 0 && (
        <SummaryPill label="Cobertura limitada" value={summary.limited} total={summary.total} tone="muted" />
      )}
    </div>
  );
}

function TestedCell({ row }: { row: OwaspCoverageRow }) {
  if (row.limited_coverage) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex items-center gap-1.5 text-sm text-warning">
            <AlertTriangle className="h-3.5 w-3.5" />
            Limitada
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs text-left">
          Esta categoria exige revisão de design/código ou acesso a logs internos — não é
          detectável remotamente de forma confiável. Não testada neste scan nem em nenhum outro
          modo de varredura do Byakugan hoje.
        </TooltipContent>
      </Tooltip>
    );
  }
  return row.tested ? (
    <span className="inline-flex items-center gap-1.5 text-sm text-success">
      <Check className="h-3.5 w-3.5" />
      Sim
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 text-sm text-muted-foreground">
      <Minus className="h-3.5 w-3.5" />
      Não
    </span>
  );
}

function FoundCell({ row }: { row: OwaspCoverageRow }) {
  if (row.findings === 0) return <span className="text-sm text-muted-foreground">—</span>;
  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-sm tabular-nums text-foreground">{row.findings}</span>
      {row.highest_severity && <SeverityBadge severity={row.highest_severity} />}
    </div>
  );
}

function ProvenCell({ row }: { row: OwaspCoverageRow }) {
  if (!row.proven) return <span className="text-sm text-muted-foreground">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-destructive/40 bg-destructive/10 px-2.5 py-0.5 text-xs font-semibold text-destructive">
      <Crosshair className="h-3.5 w-3.5" />
      Comprovado
    </span>
  );
}

function EditionTable({ rows }: { rows: OwaspCoverageRow[] }) {
  return (
    <div className="glass overflow-x-auto p-0">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Categoria</TableHead>
            <TableHead>Testada</TableHead>
            <TableHead>Encontrada</TableHead>
            <TableHead>Prova de impacto</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={row.code}>
              <TableCell className="max-w-sm">
                <span className="font-mono text-xs text-muted-foreground">{row.code}</span>
                <p className="font-medium text-foreground">{row.label}</p>
              </TableCell>
              <TableCell>
                <TestedCell row={row} />
              </TableCell>
              <TableCell>
                <FoundCell row={row} />
              </TableCell>
              <TableCell>
                <ProvenCell row={row} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

export function OwaspCoverageMatrix({ coverage }: { coverage: OwaspCoverage }) {
  const editions: OwaspEdition[] = ["2025", "2021"];
  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">
        Cobertura deste scan apenas — categorias sem achado não significam ausência de
        vulnerabilidade, significam que nada foi encontrado pelos checks executados aqui.
      </p>
      {editions.map((edition) => (
        <div key={edition} className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-foreground">OWASP Top 10 · {edition}</h3>
            <EditionSummaryBar summary={coverage.summary[edition]} />
          </div>
          <EditionTable rows={coverage[edition]} />
        </div>
      ))}
    </div>
  );
}
