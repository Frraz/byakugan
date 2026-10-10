/** Estado de autenticação (tokens + usuário), persistido em localStorage. */

import { create } from "zustand";
import { persist } from "zustand/middleware";

import type { User } from "../lib/types";

interface AuthState {
  access: string | null;
  refresh: string | null;
  user: User | null;
  /** True quando a sessão foi encerrada por falha de refresh (não por logout manual). */
  sessionExpired: boolean;
  setSession: (data: { access: string; refresh: string; user: User }) => void;
  setAccess: (access: string) => void;
  /** Encerra a sessão local. `expired: true` identifica um encerramento forçado
   *  (refresh falhou), usado pela LoginPage para exibir um aviso claro. */
  clear: (opts?: { expired?: boolean }) => void;
  setSessionExpired: (value: boolean) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      access: null,
      refresh: null,
      user: null,
      sessionExpired: false,
      setSession: ({ access, refresh, user }) =>
        set({ access, refresh, user, sessionExpired: false }),
      setAccess: (access) => set({ access }),
      clear: (opts) =>
        set({ access: null, refresh: null, user: null, sessionExpired: Boolean(opts?.expired) }),
      setSessionExpired: (value) => set({ sessionExpired: value }),
    }),
    { name: "byakugan-auth", partialize: (s) => ({ access: s.access, refresh: s.refresh, user: s.user }) },
  ),
);

export const isAuthenticated = () => Boolean(useAuthStore.getState().access);
