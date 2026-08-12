/** Resolve as cores dos tokens CSS para uso no recharts (reativo ao tema). */

import { useEffect, useState } from "react";

import { useThemeStore } from "@/store/theme";

const TOKENS = [
  "destructive",
  "sev-high",
  "warning",
  "primary",
  "sev-info",
  "accent",
  "success",
  "foreground",
  "muted-foreground",
  "border",
  "card",
] as const;

type Token = (typeof TOKENS)[number];
export type ChartColors = Record<Token, string>;

function read(): ChartColors {
  const style = getComputedStyle(document.documentElement);
  const out = {} as ChartColors;
  for (const token of TOKENS) {
    const value = style.getPropertyValue(`--${token}`).trim();
    out[token] = value ? `hsl(${value})` : "#888";
  }
  return out;
}

export function useChartColors(): ChartColors {
  const theme = useThemeStore((s) => s.theme);
  const [colors, setColors] = useState<ChartColors>(() =>
    typeof document === "undefined" ? ({} as ChartColors) : read(),
  );
  useEffect(() => {
    setColors(read());
  }, [theme]);
  return colors;
}
