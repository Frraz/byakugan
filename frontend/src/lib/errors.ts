/** Helpers para traduzir erros da API (DRF) em mensagens e erros por campo. */

import { ApiError } from "./api";

/** Mensagem legível de qualquer erro (para toasts). */
export function errorMessage(error: unknown, fallback = "Ocorreu um erro inesperado."): string {
  if (error instanceof ApiError) {
    const data = error.data;
    if (typeof data === "string" && data) return data;
    if (data && typeof data === "object") {
      const record = data as Record<string, unknown>;
      if (typeof record.detail === "string") return record.detail;
      const first = Object.values(record)[0];
      if (Array.isArray(first) && typeof first[0] === "string") return first[0];
      if (typeof first === "string") return first;
    }
    return error.message;
  }
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}

/** Extrai erros por campo de um ApiError do DRF (`{campo: [msg]}`). */
export function fieldErrors(error: unknown): Record<string, string> {
  if (!(error instanceof ApiError) || !error.data || typeof error.data !== "object") return {};
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(error.data as Record<string, unknown>)) {
    if (key === "detail") continue;
    if (Array.isArray(value) && typeof value[0] === "string") out[key] = value[0];
    else if (typeof value === "string") out[key] = value;
  }
  return out;
}
