/**
 * Cliente HTTP do Byakugan.
 * - Injeta o access token (Bearer) automaticamente.
 * - Em 401, tenta renovar via refresh token uma vez e repete a requisição.
 * A URL da API vem de VITE_API_BASE_URL (ver .env.example).
 */

import { useAuthStore } from "../store/auth";

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api";

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  time: string;
}

export class ApiError extends Error {
  status: number;
  data: unknown;
  constructor(status: number, data: unknown) {
    super(typeof data === "object" && data && "detail" in data ? String((data as { detail: unknown }).detail) : `API respondeu ${status}`);
    this.status = status;
    this.data = data;
  }
}

let pendingRefresh: { refresh: string; promise: Promise<string | null> } | null = null;

async function renewAccessToken(): Promise<string | null> {
  const { refresh, setAccess, clear } = useAuthStore.getState();
  if (!refresh) { clear({ expired: true }); return null; }
  const resp = await fetch(`${API_BASE_URL}/auth/refresh/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh }),
  });
  if (useAuthStore.getState().refresh !== refresh) return null;
  if (!resp.ok) {
    clear({ expired: true });
    return null;
  }
  const data = (await resp.json()) as { access: string };
  if (useAuthStore.getState().refresh !== refresh) return null;
  setAccess(data.access);
  return data.access;
}

function refreshAccessToken(): Promise<string | null> {
  const refresh = useAuthStore.getState().refresh ?? "";
  if (pendingRefresh?.refresh === refresh) return pendingRefresh.promise;
  const promise = renewAccessToken().finally(() => {
    if (pendingRefresh?.promise === promise) pendingRefresh = null;
  });
  pendingRefresh = { refresh, promise };
  return promise;
}

type ParamValue = string | number | boolean | null | undefined;

interface RequestOptions {
  method?: string;
  body?: unknown;
  auth?: boolean;
  params?: Record<string, ParamValue>;
}

export async function apiFetch<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, auth = true, params } = opts;

  const url = new URL(`${API_BASE_URL}${path}`, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
    }
  }

  const doRequest = async (token: string | null): Promise<Response> => {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth && token) headers.Authorization = `Bearer ${token}`;
    return fetch(url.toString(), {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  };

  const sessionRefresh = useAuthStore.getState().refresh;
  let token = useAuthStore.getState().access;
  let resp = await doRequest(token);

  if (resp.status === 401 && auth && useAuthStore.getState().refresh === sessionRefresh) {
    const latestToken = useAuthStore.getState().access;
    token = latestToken && latestToken !== token ? latestToken : await refreshAccessToken();
    if (token) resp = await doRequest(token);
    if (resp.status === 401 && useAuthStore.getState().refresh === sessionRefresh) useAuthStore.getState().clear({ expired: true });
  }

  if (resp.status === 204 || resp.status === 205) return undefined as T;

  const data = resp.headers.get("content-type")?.includes("application/json")
    ? await resp.json()
    : await resp.text();

  if (!resp.ok) throw new ApiError(resp.status, data);
  return data as T;
}

/** Health check público. */
export async function fetchHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>("/health/", { auth: false });
}

/**
 * Busca um artefato binário autenticado (ex.: relatório PDF/JSON) como Blob.
 * Reaproveita o mesmo fluxo de auth/refresh do `apiFetch`. Preserva o
 * `new URL(..., window.location.origin)` — necessário quando VITE_API_BASE_URL
 * é relativo em produção (ver memória de deploy).
 */
export async function fetchBlob(path: string): Promise<Blob> {
  const url = new URL(`${API_BASE_URL}${path}`, window.location.origin);

  const doRequest = (token: string | null) =>
    fetch(url.toString(), { headers: token ? { Authorization: `Bearer ${token}` } : {} });

  const sessionRefresh = useAuthStore.getState().refresh;
  let token = useAuthStore.getState().access;
  let resp = await doRequest(token);

  if (resp.status === 401 && useAuthStore.getState().refresh === sessionRefresh) {
    const latestToken = useAuthStore.getState().access;
    token = latestToken && latestToken !== token ? latestToken : await refreshAccessToken();
    if (token) resp = await doRequest(token);
    if (resp.status === 401 && useAuthStore.getState().refresh === sessionRefresh) useAuthStore.getState().clear({ expired: true });
  }

  if (!resp.ok) throw new ApiError(resp.status, await resp.text());
  return resp.blob();
}

/**
 * Baixa um artefato binário (ex.: relatório PDF/CSV) e dispara o download no
 * navegador. Separado de `apiFetch` porque a resposta não é JSON.
 */
export async function downloadFile(path: string, filename: string): Promise<void> {
  const blob = await fetchBlob(path);
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objectUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(objectUrl);
}
