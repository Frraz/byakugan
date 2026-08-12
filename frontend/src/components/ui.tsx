/** Kit de UI do Byakugan — dark-first, glassmorphism, neon accents (ver docs/ui.md). */

import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
} from "react";

import type { ScanStatus, Severity } from "../lib/types";

function cx(...parts: Array<string | false | undefined>) {
  return parts.filter(Boolean).join(" ");
}

// --- Glass panel / Card ---

export function GlassPanel({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={cx("glass p-5", className)}>{children}</div>;
}

// --- Button ---

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "neon" | "ghost" | "danger";
};

export function Button({ variant = "primary", className, ...props }: ButtonProps) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition disabled:opacity-50 disabled:pointer-events-none focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/60";
  const variants = {
    primary: "bg-primary text-navy hover:shadow-glow hover:brightness-110",
    neon: "border border-primary/60 text-primary hover:bg-primary/10 hover:shadow-glow",
    ghost: "text-muted hover:text-foreground hover:bg-white/5",
    danger: "border border-danger/60 text-danger hover:bg-danger/10",
  };
  return <button className={cx(base, variants[variant], className)} {...props} />;
}

// --- Inputs ---

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cx(
        "w-full rounded-xl border border-border bg-surface-2/60 px-3 py-2 text-sm text-foreground placeholder:text-muted focus:border-primary/60 focus:outline-none focus:ring-1 focus:ring-primary/40",
        className,
      )}
      {...props}
    />
  );
}

export function Select({ className, children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cx(
        "rounded-xl border border-border bg-surface-2/60 px-3 py-2 text-sm text-foreground focus:border-primary/60 focus:outline-none",
        className,
      )}
      {...props}
    >
      {children}
    </select>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium uppercase tracking-wide text-muted">{label}</span>
      {children}
    </label>
  );
}

// --- Badges ---

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-danger/15 text-danger border-danger/40",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-warning/15 text-warning border-warning/40",
  low: "bg-primary/15 text-primary border-primary/40",
  info: "bg-sev-info/15 text-slate-300 border-sev-info/40",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold capitalize",
        SEVERITY_STYLES[severity],
      )}
      aria-label={`Severidade ${severity}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {severity}
    </span>
  );
}

const STATUS_STYLES: Record<ScanStatus, string> = {
  pending: "bg-slate-500/15 text-slate-300 border-slate-500/40",
  running: "bg-primary/15 text-primary border-primary/40",
  completed: "bg-success/15 text-success border-success/40",
  failed: "bg-danger/15 text-danger border-danger/40",
  cancelled: "bg-warning/15 text-warning border-warning/40",
};

const STATUS_LABELS: Record<ScanStatus, string> = {
  pending: "Pendente",
  running: "Executando",
  completed: "Concluído",
  failed: "Falhou",
  cancelled: "Cancelado",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        STATUS_STYLES[status],
      )}
    >
      <span
        className={cx("h-1.5 w-1.5 rounded-full bg-current", status === "running" && "animate-pulse")}
        aria-hidden
      />
      {STATUS_LABELS[status]}
    </span>
  );
}

// --- KPI tile ---

export function StatCard({
  label,
  value,
  accent = "primary",
  icon,
}: {
  label: string;
  value: ReactNode;
  accent?: "primary" | "danger" | "warning" | "success" | "accent";
  icon?: ReactNode;
}) {
  const accents = {
    primary: "text-primary",
    danger: "text-danger",
    warning: "text-warning",
    success: "text-success",
    accent: "text-accent",
  };
  return (
    <div className="glass flex items-center justify-between p-4">
      <div>
        <p className="text-xs font-medium uppercase tracking-wide text-muted">{label}</p>
        <p className={cx("mt-1 text-2xl font-bold", accents[accent])}>{value}</p>
      </div>
      {icon && <div className={cx("opacity-70", accents[accent])}>{icon}</div>}
    </div>
  );
}

// --- Table primitives ---

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="glass thin-scroll overflow-x-auto p-0">
      <table className="w-full text-left text-sm">{children}</table>
    </div>
  );
}

export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <th
      className={cx(
        "border-b border-border px-4 py-3 text-xs font-semibold uppercase tracking-wide text-muted",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cx("border-b border-border/50 px-4 py-3 text-foreground", className)}>{children}</td>;
}

// --- States ---

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("animate-pulse rounded-lg bg-white/5", className)} />;
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="glass flex flex-col items-center justify-center gap-1 p-10 text-center">
      <p className="font-semibold text-foreground">{title}</p>
      {hint && <p className="text-sm text-muted">{hint}</p>}
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger">
      {message}
    </div>
  );
}
