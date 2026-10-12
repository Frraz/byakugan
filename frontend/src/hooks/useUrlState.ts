/** Mantém filtros/página no endereço para preservar a navegação de volta. */
import { useCallback } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";

// Agrupa alterações do mesmo evento: setSearchParams não enfileira callbacks,
// e o reset de página não deve sobrescrever o filtro recém-definido.
let pending: { params: URLSearchParams; pathname: string; hash: string; commit: (to: string) => void } | null = null;

export function useUrlState<T extends string | number>(key: string, initial: T): [T, (value: T | ((current: T) => T)) => void] {
  const [params] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const raw = params.get(key);
  const value = (typeof initial === "number"
    ? raw && /^\d+$/.test(raw) && Number(raw) > 0 ? Number(raw) : initial
    : raw ?? initial) as T;
  const setValue = useCallback((incoming: T | ((current: T) => T)) => {
    const next = typeof incoming === "function" ? incoming(value) : incoming;
    if (!pending || pending.pathname !== location.pathname) {
      const batch = { params: new URLSearchParams(location.search), pathname: location.pathname, hash: location.hash, commit: (to: string) => navigate(to, { replace: true }) };
      pending = batch;
      queueMicrotask(() => {
        if (pending !== batch) return;
        pending = null;
        const search = batch.params.toString();
        batch.commit(`${batch.pathname}${search ? `?${search}` : ""}${batch.hash}`);
      });
    }
    if (next === initial) pending.params.delete(key);
    else pending.params.set(key, String(next));
  }, [key, initial, value, location.pathname, location.search, location.hash, navigate]);
  return [value, setValue];
}
