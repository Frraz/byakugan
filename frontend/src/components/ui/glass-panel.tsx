/** Painel glass: superfície translúcida com blur e borda sutil (docs/ui.md). */

import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export function GlassPanel({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("glass p-5", className)} {...props} />;
}
