import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiFetch, fetchBlob } from "../api";
import { useAuthStore } from "@/store/auth";

const user = { id: "user-1", email: "lab@example.test", role: "analyst" as const, is_active: true };
const response = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });

beforeEach(() => useAuthStore.getState().setSession({ access: "old-access", refresh: "refresh-token", user }));
afterEach(() => { vi.unstubAllGlobals(); useAuthStore.getState().clear(); });

describe("authenticated requests", () => {
  it("shares one refresh across simultaneous JSON and binary requests", async () => {
    let refreshes = 0;
    const fetch = vi.fn(async (url: string, options?: RequestInit) => {
      if (String(url).includes("/auth/refresh/")) { refreshes++; await Promise.resolve(); return response({ access: "new-access" }); }
      return new Headers(options?.headers).get("Authorization") === "Bearer new-access" ? response({ ok: true }) : response({ detail: "Expired" }, 401);
    });
    vi.stubGlobal("fetch", fetch);
    const [data, blob] = await Promise.all([apiFetch("/targets/"), fetchBlob("/reports/r/download/")]);
    expect(data).toEqual({ ok: true });
    expect(blob.size).toBeGreaterThan(0);
    expect(refreshes).toBe(1);
    expect(useAuthStore.getState().access).toBe("new-access");
  });

  it("ends the session when no refresh token exists", async () => {
    useAuthStore.setState({ refresh: null });
    vi.stubGlobal("fetch", vi.fn(async () => response({ detail: "Expired" }, 401)));
    await expect(apiFetch("/targets/")).rejects.toMatchObject({ status: 401 });
    expect(useAuthStore.getState()).toMatchObject({ access: null, user: null, sessionExpired: true });
  });

  it("does not erase a newly authenticated session after an old request returns 401", async () => {
    let complete!: (value: Response) => void;
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>((resolve) => { complete = resolve; })));
    const request = apiFetch("/targets/");
    useAuthStore.getState().setSession({ access: "different-access", refresh: "different-refresh", user: { ...user, id: "user-2" } });
    complete(response({ detail: "Expired" }, 401));
    await expect(request).rejects.toMatchObject({ status: 401 });
    expect(useAuthStore.getState().access).toBe("different-access");
  });
});
