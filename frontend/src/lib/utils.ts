/** Utilitários compartilhados de UI. */

import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/** Combina classes condicionalmente resolvendo conflitos de Tailwind. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
