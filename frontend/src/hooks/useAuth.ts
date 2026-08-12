/** Hooks de autenticação: login e logout. */

import { useMutation } from "@tanstack/react-query";

import { apiFetch } from "../lib/api";
import type { LoginResponse } from "../lib/types";
import { useAuthStore } from "../store/auth";

export function useLogin() {
  const setSession = useAuthStore((s) => s.setSession);
  return useMutation({
    mutationFn: (creds: { email: string; password: string }) =>
      apiFetch<LoginResponse>("/auth/login/", {
        method: "POST",
        body: creds,
        auth: false,
      }),
    onSuccess: (data) => setSession(data),
  });
}

export function useLogout() {
  return useMutation({
    mutationFn: async () => {
      const { refresh } = useAuthStore.getState();
      if (refresh) {
        try {
          await apiFetch("/auth/logout/", { method: "POST", body: { refresh } });
        } catch {
          /* mesmo em erro, limpamos a sessão local */
        }
      }
    },
    onSettled: () => useAuthStore.getState().clear(),
  });
}
