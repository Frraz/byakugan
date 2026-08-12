/** Dashboard SOC — KPIs, gráficos de risco, heatmap e scans recentes (docs/ui.md). */

import { Link, useNavigate } from "react-router-dom";
import { Boxes, Radar, ShieldAlert, Target as TargetIcon } from "lucide-react";

import { PageHeader } from "@/components/PageHeader";
import { CategoryHeatmap } from "@/components/charts/CategoryHeatmap";
import { SeverityDonut } from "@/components/charts/SeverityDonut";
import { EmptyState } from "@/components/ui/empty-state";
import { GlassPanel } from "@/components/ui/glass-panel";
import { Progress } from "@/components/ui/progress";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { StatCard } from "@/components/ui/stat-card";
import { StatusBadge } from "@/components/ui/status-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAssets, useRiskOverview, useScans, useTargets } from "@/hooks/useData";
import { usePageTitle } from "@/hooks/usePageTitle";
import { formatRelative } from "@/lib/format";

export function DashboardPage() {
  usePageTitle("Dashboard");
  const navigate = useNavigate();
  const assets = useAssets();
  const scans = useScans();
  const targets = useTargets();
  const risk = useRiskOverview(5);

  const scanList = scans.data?.results ?? [];
  const active = scanList.filter((s) => s.status === "running" || s.status === "pending").length;
  const summary = risk.data?.summary;
  const topAssets = risk.data?.top_assets ?? [];
  const severity = summary?.severity ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  return (
    <div>
      <PageHeader title="Dashboard" description="Visão consolidada do ambiente monitorado." />

      {/* KPIs principais */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Ativos"
          value={assets.data?.count ?? "—"}
          icon={Boxes}
          onClick={() => navigate("/assets")}
        />
        <StatCard
          label="Alvos"
          value={targets.data?.count ?? "—"}
          accent="accent"
          icon={TargetIcon}
          onClick={() => navigate("/targets")}
        />
        <StatCard
          label="Scans ativos"
          value={active}
          accent="primary"
          icon={Radar}
          onClick={() => navigate("/scans")}
        />
        <StatCard
          label="Findings críticos"
          value={summary?.severity.critical ?? "—"}
          accent="danger"
          icon={ShieldAlert}
          onClick={() => navigate("/vulnerabilities")}
        />
      </div>

      {/* Risco + distribuição */}
      <div className="mt-6 grid gap-4 lg:grid-cols-3">
        <GlassPanel className="space-y-4">
          <h2 className="text-sm font-semibold text-foreground">Risk Score</h2>
          {risk.isLoading || !summary ? (
            <Skeleton className="h-24 w-full" />
          ) : (
            <>
              <div className="flex items-end justify-between">
                <span className="text-4xl font-bold tabular-nums text-foreground">
                  {summary.risk_score}
                  <span className="text-lg text-muted-foreground">/100</span>
                </span>
                <SeverityBadge severity={summary.risk_level} />
              </div>
              <Progress value={summary.risk_score} className="h-2" />
              <p className="text-xs text-muted-foreground">
                {summary.findings} findings em {summary.assets} ativos.
              </p>
            </>
          )}
        </GlassPanel>

        <GlassPanel className="lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold text-foreground">
            Distribuição por severidade
          </h2>
          {risk.isLoading ? <Skeleton className="h-52 w-full" /> : <SeverityDonut counts={severity} />}
        </GlassPanel>
      </div>

      {/* Ativos priorizados */}
      <h2 className="mb-3 mt-8 text-lg font-semibold text-foreground">Ativos priorizados</h2>
      {risk.isLoading ? (
        <Skeleton className="h-32 w-full rounded-2xl" />
      ) : topAssets.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="Nenhum risco a priorizar"
          hint="Assim que scans de vulnerability produzirem findings, os ativos mais críticos aparecem aqui."
        />
      ) : (
        <div className="glass overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Ativo</TableHead>
                <TableHead>Risk Score</TableHead>
                <TableHead>Nível</TableHead>
                <TableHead className="text-right">Findings</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {topAssets.map((a) => (
                <TableRow key={a.asset}>
                  <TableCell>
                    <Link
                      to={`/assets/${a.asset}`}
                      className="font-medium text-primary hover:underline"
                    >
                      {a.hostname ?? a.ip ?? a.domain ?? a.asset.slice(0, 8)}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono">{a.risk_score}/100</TableCell>
                  <TableCell>
                    <SeverityBadge severity={a.risk_level} />
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-muted-foreground">
                    {a.findings}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Heatmap */}
      <h2 className="mb-3 mt-8 text-lg font-semibold text-foreground">Heatmap por categoria</h2>
      <GlassPanel>
        {risk.isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : (
          <CategoryHeatmap cells={risk.data?.heatmap ?? []} />
        )}
      </GlassPanel>

      {/* Scans recentes */}
      <h2 className="mb-3 mt-8 text-lg font-semibold text-foreground">Scans recentes</h2>
      {scans.isLoading ? (
        <Skeleton className="h-40 w-full rounded-2xl" />
      ) : scanList.length === 0 ? (
        <EmptyState icon={Radar} title="Nenhum scan ainda" hint="Cadastre um alvo e inicie uma descoberta." />
      ) : (
        <div className="glass overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Alvo</TableHead>
                <TableHead>Tipo</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Criado</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scanList.slice(0, 8).map((s) => (
                <TableRow key={s.id}>
                  <TableCell>
                    <Link to={`/scans/${s.id}`} className="font-medium text-primary hover:underline">
                      {s.target_name ?? s.target}
                    </Link>
                  </TableCell>
                  <TableCell className="capitalize text-muted-foreground">{s.scan_type}</TableCell>
                  <TableCell>
                    <StatusBadge status={s.status} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatRelative(s.created_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
