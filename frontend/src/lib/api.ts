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

async function refreshAccessToken(): Promise<string | null> {
  const { refresh, setAccess, clear } = useAuthStore.getState();
  if (!refresh) return null;
  const resp = await fetch(`${API_BASE_URL}/auth/refresh/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh }),
  });
  if (!resp.ok) {
    clear();
    return null;
  }
  const data = (await resp.json()) as { access: string };
  setAccess(data.access);
  return data.access;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  auth?: boolean;
  params?: Record<string, string | number | boolean | undefined>;
}

export async function apiFetch<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, auth = true, params } = opts;

  const url = new URL(`${API_BASE_URL}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
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

  let token = useAuthStore.getState().access;
  let resp = await doRequest(token);

  if (resp.status === 401 && auth) {
    token = await refreshAccessToken();
    if (token) resp = await doRequest(token);
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
