/** Badge do tipo de scan — ícone + rótulo, cor sutil por tipo. */

import type { ComponentType } from "react";
import { Fingerprint, Layers, Radar, ShieldAlert } from "lucide-react";

import type { ScanType } from "@/lib/types";
import { cn } from "@/lib/utils";

const META: Record<ScanType, { label: string; icon: ComponentType<{ className?: string }>; className: string }> = {
  discovery: { label: "Discovery", icon: Radar, className: "bg-sev-info/10 text-sev-info border-sev-info/30" },
  fingerprint: { label: "Fingerprint", icon: Fingerprint, className: "bg-accent/10 text-accent border-accent/30" },
  vulnerability: { label: "Vulnerability", icon: ShieldAlert, className: "bg-warning/10 text-warning border-warning/30" },
  full: { label: "Full", icon: Layers, className: "bg-primary/10 text-primary border-primary/30" },
};

export function ScanTypeBadge({ type, className }: { type: ScanType; className?: string }) {
  const meta = META[type];
  const Icon = meta.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        meta.className,
        className,
      )}
    >
      <Icon className="h-3.5 w-3.5" />
      {meta.label}
    </span>
  );
}

export const SCAN_TYPE_LABELS: Record<ScanType, string> = {
  discovery: "Discovery",
  fingerprint: "Fingerprint",
  vulnerability: "Vulnerability",
  full: "Full",
};
