/** Dashboard SOC — KPI tiles + scans recentes (docs/ui.md). */

import { Link } from "react-router-dom";

import { PageHeader } from "../components/PageHeader";
import { AssetsIcon, ScansIcon, TargetsIcon } from "../components/icons";
import {
  EmptyState,
  Skeleton,
  StatCard,
  StatusBadge,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useAssets, useFindings, useScans, useTargets } from "../hooks/useData";

export function DashboardPage() {
  const assets = useAssets();
  const scans = useScans();
  const targets = useTargets();
  const criticalFindings = useFindings({ severity: "critical" });

  const scanList = scans.data?.results ?? [];
  const active = scanList.filter((s) => s.status === "running" || s.status === "pending").length;
  const completed = scanList.filter((s) => s.status === "completed").length;

  return (
    <div>
      <PageHeader title="Dashboard" description="Visão consolidada do ambiente monitorado." />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard label="Ativos" value={assets.data?.count ?? "—"} icon={<AssetsIcon width={28} height={28} />} />
        <StatCard label="Scans ativos" value={active} accent="primary" icon={<ScansIcon width={28} height={28} />} />
        <StatCard label="Scans concluídos" value={completed} accent="success" />
        <StatCard label="Alvos" value={targets.data?.count ?? "—"} accent="accent" icon={<TargetsIcon width={28} height={28} />} />
        <StatCard label="Findings críticos" value={criticalFindings.data?.count ?? "—"} accent="danger" />
      </div>

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
