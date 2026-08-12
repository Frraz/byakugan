/** Badge de categoria de finding (rótulo PT-BR, espelha backend FindingCategory). */

import type { FindingCategory } from "@/lib/types";
import { cn } from "@/lib/utils";

const LABELS: Record<FindingCategory, string> = {
  software: "Software (CVE)",
  service: "Serviço de rede",
  network: "Rede",
  credential: "Credencial",
  tls: "TLS",
  certificate: "Certificado",
  dns: "DNS",
  "email-security": "Segurança de e-mail",
  subdomain: "Subdomínio",
  "web-headers": "Headers HTTP",
  cookie: "Cookie",
  cors: "CORS",
  exposure: "Exposição",
  "http-method": "Método HTTP",
  injection: "Injeção",
};

/** Rótulo amigável de uma categoria — cai no valor bruto se fora do enum conhecido. */
export function categoryLabel(category: string): string {
  return LABELS[category as FindingCategory] ?? category;
}

export function CategoryBadge({ category, className }: { category: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground",
        className,
      )}
    >
      {categoryLabel(category)}
    </span>
  );
}

export const CATEGORY_LABELS = LABELS;
