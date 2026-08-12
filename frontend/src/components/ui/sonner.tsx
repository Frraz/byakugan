/** Toaster global (sonner) sincronizado com o tema do Byakugan. */

import { Toaster as SonnerToaster } from "sonner";

import { useThemeStore } from "@/store/theme";

export function Toaster() {
  const theme = useThemeStore((s) => s.theme);
  return (
    <SonnerToaster
      theme={theme}
      position="top-right"
      richColors
      closeButton
      toastOptions={{
        classNames: {
          toast: "font-sans",
        },
      }}
    />
  );
}
