/** Donut de distribuição de findings por severidade (paleta canônica docs/ui.md). */

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import { SEVERITY_LABELS, SEVERITY_ORDER } from "@/components/ui/severity-badge";
import { useChartColors } from "@/hooks/useChartColors";
import type { SeverityCounts, Severity } from "@/lib/types";

const COLOR_TOKEN: Record<Severity, keyof ReturnType<typeof useChartColors>> = {
  critical: "destructive",
  high: "sev-high",
  medium: "warning",
  low: "primary",
  info: "sev-info",
};

export function SeverityDonut({ counts }: { counts: SeverityCounts }) {
  const colors = useChartColors();
  const data = SEVERITY_ORDER.map((sev) => ({
    key: sev,
    name: SEVERITY_LABELS[sev],
    value: counts[sev],
    fill: colors[COLOR_TOKEN[sev]],
  })).filter((d) => d.value > 0);

  const total = data.reduce((sum, d) => sum + d.value, 0);

  if (total === 0) {
    return (
      <div className="flex h-52 items-center justify-center text-sm text-muted-foreground">
        Sem findings para exibir
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row">
      <div className="relative h-52 w-52 shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              stroke={colors.card}
              strokeWidth={2}
            >
              {data.map((d) => (
                <Cell key={d.key} fill={d.fill} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: colors.card,
                border: `1px solid ${colors.border}`,
                borderRadius: 12,
                color: colors.foreground,
                fontSize: 12,
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold tabular-nums text-foreground">{total}</span>
          <span className="text-xs text-muted-foreground">findings</span>
        </div>
      </div>
      <ul className="grid flex-1 gap-1.5">
        {data.map((d) => (
          <li key={d.key} className="flex items-center justify-between gap-3 text-sm">
            <span className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: d.fill }} />
              {d.name}
            </span>
            <span className="font-mono tabular-nums text-muted-foreground">{d.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
