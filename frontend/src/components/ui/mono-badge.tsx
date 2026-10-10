/** Badge monoespaçado para códigos curtos (OWASP/CWE/MITRE/CVE) — "" não renderiza nada. */

export function MonoBadge({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return (
    <span className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono text-foreground">{value}</span>
    </span>
  );
}
