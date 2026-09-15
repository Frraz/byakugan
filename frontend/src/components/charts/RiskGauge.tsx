/** Anel de Risk Score (0–100), colorido pelo nível de risco. */

import type { Severity } from "@/lib/types";

const LEVEL_COLOR: Record<Severity, string> = {
  critical: "hsl(var(--destructive))",
  high: "hsl(var(--sev-high))",
  medium: "hsl(var(--warning))",
  low: "hsl(var(--primary))",
  info: "hsl(var(--sev-info))",
};

/**
 * Anel de progresso circular preenchido de acordo com `score` (0–100), na cor
 * do `level`. Puro SVG (sem dependência); a rotação de -90° faz o preenchimento
 * começar no topo. O centro mostra o valor.
 */
export function RiskGauge({
  score,
  level,
  size = 176,
}: {
  score: number;
  level: Severity;
  size?: number;
}) {
  const stroke = 14;
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, score)) / 100;
  const filled = pct * circumference;
  const color = LEVEL_COLOR[level] ?? LEVEL_COLOR.info;

  return (
    <div
      className="relative inline-flex items-center justify-center"
      style={{ width: size, height: size }}
    >
      <svg
        width={size}
        height={size}
        className="-rotate-90"
        role="img"
        aria-label={`Risk score ${score} de 100`}
      >
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="hsl(var(--secondary))" strokeWidth={stroke} />
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          className="transition-[stroke-dasharray] duration-700 motion-reduce:transition-none"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold leading-none tabular-nums text-foreground">{score}</span>
        <span className="mt-1 text-xs text-muted-foreground">/ 100</span>
      </div>
    </div>
  );
}
