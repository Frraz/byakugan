/** Tema da UI (dark padrão / light), persistido e aplicado à raiz do HTML. */

import { create } from "zustand";
import { persist } from "zustand/middleware";

type Theme = "dark" | "light";

interface ThemeState {
  theme: Theme;
  toggle: () => void;
  apply: () => void;
}

function setRootClass(theme: Theme) {
  const root = document.documentElement;
  root.classList.toggle("light", theme === "light");
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set, get) => ({
      theme: "dark",
      toggle: () => {
        const next = get().theme === "dark" ? "light" : "dark";
        set({ theme: next });
        setRootClass(next);
      },
      apply: () => setRootClass(get().theme),
    }),
    { name: "byakugan-theme" },
  ),
);
