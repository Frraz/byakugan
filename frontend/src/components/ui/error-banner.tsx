/** Banner de erro inline. */

import { AlertTriangle } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "./button";

export function ErrorBanner({ message, className, onRetry }: { message: string; className?: string; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-wrap items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive",
        className,
      )}
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <span className="min-w-0 flex-1 break-words">{message}</span>
      {onRetry && <Button variant="outline" size="sm" onClick={onRetry}>Tentar novamente</Button>}
    </div>
  );
}
