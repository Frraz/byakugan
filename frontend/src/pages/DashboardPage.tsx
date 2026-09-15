/** Dashboard SOC — command center: KPIs, risco, heatmap e scans recentes. */

import { Link, useNavigate } from "react-router-dom";
import {
  Activity,
  Boxes,
  Crosshair,
  Flame,
  Grid3x3,
  PieChart,
  Plus,
  Radar,
  ShieldAlert,
  Target as TargetIcon,
} from "lucide-react";

import { PageHeader } from "@/components/PageHeader";
import { CategoryHeatmap } from "@/components/charts/CategoryHeatmap";
import { RiskGauge } from "@/components/charts/RiskGauge";
import { SeverityDonut } from "@/components/charts/SeverityDonut";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { GlassPanel } from "@/components/ui/glass-panel";
import { SectionHeading } from "@/components/ui/section-heading";
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
  const totalFindings = summary?.findings ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="Visão consolidada do ambiente monitorado."
        actions={
          <Button onClick={() => navigate("/scans")}>
            <Plus className="h-4 w-4" />
            Novo scan
          </Button>
        }
      />

      {/* KPIs principais */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Ativos descobertos"
          value={assets.data?.count ?? "—"}
          icon={Boxes}
          accent="primary"
          loading={assets.isLoading}
        />
        <StatCard
          label="Alvos"
          value={targets.data?.count ?? "—"}
          hint="Gerenciar alvos"
          accent="accent"
          icon={TargetIcon}
          onClick={() => navigate("/targets")}
          loading={targets.isLoading}
        />
        <StatCard
          label="Scans ativos"
          value={active}
          hint={`${scanList.length} no total`}
          accent="primary"
          icon={Radar}
          onClick={() => navigate("/scans")}
          loading={scans.isLoading}
        />
        <StatCard
          label="Findings críticos"
          value={summary?.severity.critical ?? "—"}
          hint={`${totalFindings} findings no total`}
          accent="danger"
          icon={ShieldAlert}
          onClick={() => navigate("/vulnerabilities")}
          loading={risk.isLoading}
        />
      </div>

      {/* Risco + distribuição por severidade */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="glass-elevated flex flex-col p-5">
          <SectionHeading title="Risk Score" icon={Flame} />
          {risk.isLoading || !summary ? (
            <Skeleton className="mx-auto h-44 w-44 rounded-full" />
          ) : (
            <div className="flex flex-1 flex-col items-center justify-center gap-4 py-2">
              <RiskGauge score={Math.round(summary.risk_score)} level={summary.risk_level} />
              <div className="flex items-center gap-2">
                <SeverityBadge severity={summary.risk_level} />
                <span className="text-xs text-muted-foreground">
                  {summary.findings} findings · {summary.assets} ativos
                </span>
              </div>
            </div>
          )}
        </div>

        <GlassPanel className="flex flex-col lg:col-span-2">
          <SectionHeading title="Distribuição por severidade" icon={PieChart} />
          {risk.isLoading ? (
            <Skeleton className="h-52 w-full" />
          ) : (
            <div className="flex flex-1 items-center justify-center">
              <SeverityDonut counts={severity} />
            </div>
          )}
        </GlassPanel>
      </div>

      {/* Ativos priorizados + Heatmap */}
      <div className="grid gap-4 lg:grid-cols-5">
        <GlassPanel className="lg:col-span-2">
          <SectionHeading
            title="Ativos priorizados"
            icon={ShieldAlert}
            action={
              topAssets.length > 0 && (
                <Link to="/vulnerabilities" className="text-xs text-primary hover:underline">
                  Ver todos
                </Link>
              )
            }
          />
          {risk.isLoading ? (
            <Skeleton className="h-40 w-full" />
          ) : topAssets.length === 0 ? (
            <EmptyState
              icon={ShieldAlert}
              title="Nenhum risco a priorizar"
              hint="Ativos mais críticos aparecem aqui após scans de vulnerability."
            />
          ) : (
            <ul className="space-y-2">
              {topAssets.map((a) => (
                <li key={a.asset}>
                  <Link
                    to={`/assets/${a.asset}`}
                    className="flex items-center gap-3 rounded-xl border border-border bg-popover/40 p-2.5 transition-colors hover:border-primary/40"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-foreground">
                        {a.hostname ?? a.ip ?? a.domain ?? a.asset.slice(0, 8)}
                      </p>
                      <p className="text-xs text-muted-foreground">{a.findings} findings</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm tabular-nums text-foreground">
                        {a.risk_score}
                      </span>
                      <SeverityBadge severity={a.risk_level} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </GlassPanel>

        <GlassPanel className="lg:col-span-3">
          <SectionHeading title="Heatmap por categoria" icon={Grid3x3} />
          {risk.isLoading ? (
            <Skeleton className="h-40 w-full" />
          ) : (risk.data?.heatmap ?? []).length === 0 ? (
            <EmptyState
              icon={Grid3x3}
              title="Sem dados de risco"
              hint="O heatmap se preenche conforme os findings são categorizados."
            />
          ) : (
            <div className="overflow-x-auto">
              <CategoryHeatmap cells={risk.data?.heatmap ?? []} />
            </div>
          )}
        </GlassPanel>
      </div>

      {/* Scans recentes */}
      <GlassPanel>
        <SectionHeading
          title="Scans recentes"
          icon={Activity}
          action={
            <Link to="/scans" className="text-xs text-primary hover:underline">
              Ver todos
            </Link>
          }
        />
        {scans.isLoading ? (
          <Skeleton className="h-40 w-full" />
        ) : scanList.length === 0 ? (
          <EmptyState
            icon={Radar}
            title="Nenhum scan ainda"
            hint="Cadastre um alvo e inicie uma descoberta."
            action={
              <Button variant="secondary" onClick={() => navigate("/scans")}>
                <Crosshair className="h-4 w-4" />
                Iniciar scan
              </Button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Alvo</TableHead>
                  <TableHead>Tipo</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Criado</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scanList.slice(0, 8).map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <Link
                        to={`/scans/${s.id}`}
                        className="font-medium text-primary hover:underline"
                      >
                        {s.target_name ?? s.target}
                      </Link>
                    </TableCell>
                    <TableCell className="capitalize text-muted-foreground">{s.scan_type}</TableCell>
                    <TableCell>
                      <StatusBadge status={s.status} />
                    </TableCell>
                    <TableCell className="text-right text-muted-foreground">
                      {formatRelative(s.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </GlassPanel>
    </div>
  );
}
