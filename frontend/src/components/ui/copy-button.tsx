/** Botão de copiar — usado sobre blocos monoespaçados de evidência/código. */

import { useState } from "react";
import { Check, Copy } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function CopyButton({ value, label = "Copiar", className }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  const onClick = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard indisponível (ex.: contexto não seguro) — falha silenciosa,
      // o texto continua selecionável manualmente no bloco.
    }
  };

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      className={cn("h-7 w-7 text-muted-foreground hover:text-foreground", className)}
      onClick={onClick}
      aria-label={copied ? "Copiado" : label}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
    </Button>
  );
}
