/** Dashboard SOC — KPI tiles, risco priorizado e heatmap (docs/ui.md). */

import { Link } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";
import { AssetsIcon, ScansIcon, TargetsIcon } from "../components/icons";
import {
  EmptyState,
  SeverityBadge,
  Skeleton,
  StatCard,
  StatusBadge,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useAssets, useRiskOverview, useScans, useTargets } from "../hooks/useData";
import type { HeatmapCell, Severity } from "../lib/types";

const RISK_ACCENT: Record<Severity, "danger" | "warning" | "primary" | "success" | "accent"> = {
  critical: "danger",
  high: "warning",
  medium: "accent",
  low: "primary",
  info: "success",
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const HEATMAP_CELL_STYLES: Record<Severity, string> = {
  critical: "bg-danger/20 text-danger",
  high: "bg-sev-high/20 text-sev-high",
  medium: "bg-warning/20 text-warning",
  low: "bg-primary/20 text-primary",
  info: "bg-sev-info/20 text-slate-300",
};

function RiskHeatmap({ cells }: { cells: HeatmapCell[] }) {
  const categories = Array.from(new Set(cells.map((c) => c.category))).sort();
  const lookup = new Map(cells.map((c) => [`${c.category}|${c.severity}`, c.count]));

  if (categories.length === 0) {
    return (
      <EmptyState
        title="Sem dados para o heatmap"
        hint="Execute scans de vulnerability (ou full) para popular a matriz de risco por categoria."
      />
    );
  }

  return (
    <div className="thin-scroll overflow-x-auto">
      <table className="w-full border-separate border-spacing-1 text-sm">
        <thead>
          <tr>
            <th className="p-2 text-left text-xs uppercase tracking-wide text-muted">Categoria</th>
            {SEVERITY_ORDER.map((sev) => (
              <th
                key={sev}
                className="p-2 text-center text-xs uppercase tracking-wide text-muted"
              >
                {sev}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {categories.map((category) => (
            <tr key={category}>
              <td className="p-2 font-medium capitalize text-foreground">{category}</td>
              {SEVERITY_ORDER.map((sev) => {
                const count = lookup.get(`${category}|${sev}`) ?? 0;
                return (
                  <td
                    key={sev}
                    className={`rounded-md p-2 text-center font-mono ${
                      count > 0 ? HEATMAP_CELL_STYLES[sev] : "text-muted/40"
                    }`}
                  >
                    {count || "–"}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DashboardPage() {
  const assets = useAssets();
  const scans = useScans();
  const targets = useTargets();
  const risk = useRiskOverview(5);

  const scanList = scans.data?.results ?? [];
  const active = scanList.filter((s) => s.status === "running" || s.status === "pending").length;
  const completed = scanList.filter((s) => s.status === "completed").length;
  const summary = risk.data?.summary;
  const topAssets = risk.data?.top_assets ?? [];

  return (
    <div>
      <PageHeader title="Dashboard" description="Visão consolidada do ambiente monitorado." />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Ativos" value={assets.data?.count ?? "—"} icon={<AssetsIcon width={28} height={28} />} />
        <StatCard label="Scans ativos" value={active} accent="primary" icon={<ScansIcon width={28} height={28} />} />
        <StatCard label="Scans concluídos" value={completed} accent="success" />
        <StatCard label="Alvos" value={targets.data?.count ?? "—"} accent="accent" icon={<TargetsIcon width={28} height={28} />} />
      </div>

      <h2 className="mb-3 mt-8 text-lg font-semibold text-foreground">Risco (Correlation Engine)</h2>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Risk Score"
          value={summary ? `${summary.risk_score}/100` : "—"}
          accent={summary ? RISK_ACCENT[summary.risk_level] : "primary"}
        />
        <StatCard label="Findings críticos" value={summary?.severity.critical ?? "—"} accent="danger" />
        <StatCard label="Findings altos" value={summary?.severity.high ?? "—"} accent="warning" />
        <StatCard label="Findings médios" value={summary?.severity.medium ?? "—"} accent="accent" />
      </div>

      <h3 className="mb-3 mt-6 text-sm font-semibold uppercase tracking-wide text-muted">
        Ativos priorizados
      </h3>
      {risk.isLoading ? (
        <Skeleton className="h-32 w-full" />
      ) : topAssets.length === 0 ? (
        <EmptyState
          title="Nenhum risco a priorizar"
          hint="Assim que scans de vulnerability produzirem findings, os ativos mais críticos aparecem aqui."
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Ativo</Th>
              <Th>Risk Score</Th>
              <Th>Nível</Th>
              <Th>Findings</Th>
            </tr>
          </thead>
          <tbody>
            {topAssets.map((a) => (
              <tr key={a.asset} className="hover:bg-white/5">
                <Td>
                  <Link to={`/assets/${a.asset}`} className="font-medium text-primary hover:underline">
                    {a.hostname ?? a.ip ?? a.domain ?? a.asset.slice(0, 8)}
                  </Link>
                </Td>
                <Td className="font-mono text-foreground">{a.risk_score}/100</Td>
                <Td>
                  <SeverityBadge severity={a.risk_level} />
                </Td>
                <Td className="text-muted">{a.findings}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <h3 className="mb-3 mt-6 text-sm font-semibold uppercase tracking-wide text-muted">
        Heatmap por categoria
      </h3>
      {risk.isLoading ? <Skeleton className="h-32 w-full" /> : <RiskHeatmap cells={risk.data?.heatmap ?? []} />}

      <h2 className="mb-3 mt-8 text-lg font-semibold text-foreground">Scans recentes</h2>
      {scans.isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : scanList.length === 0 ? (
        <EmptyState title="Nenhum scan ainda" hint="Cadastre um alvo e inicie uma descoberta." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Alvo</Th>
              <Th>Tipo</Th>
              <Th>Status</Th>
              <Th>Criado</Th>
            </tr>
          </thead>
          <tbody>
            {scanList.slice(0, 8).map((s) => (
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
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
