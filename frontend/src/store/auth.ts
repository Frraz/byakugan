/** Estado de autenticação (tokens + usuário), persistido em localStorage. */

import { create } from "zustand";
import { persist } from "zustand/middleware";

import type { User } from "../lib/types";

interface AuthState {
  access: string | null;
  refresh: string | null;
  user: User | null;
  setSession: (data: { access: string; refresh: string; user: User }) => void;
  setAccess: (access: string) => void;
  clear: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      access: null,
      refresh: null,
      user: null,
      setSession: ({ access, refresh, user }) => set({ access, refresh, user }),
      setAccess: (access) => set({ access }),
      clear: () => set({ access: null, refresh: null, user: null }),
    }),
    { name: "byakugan-auth" },
  ),
);

export const isAuthenticated = () => Boolean(useAuthStore.getState().access);
