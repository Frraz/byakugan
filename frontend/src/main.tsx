import "@fontsource-variable/inter";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import App from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Toaster } from "./components/ui/sonner";
import "./index.css";
import { useThemeStore } from "./store/theme";
import { useAuthStore } from "./store/auth";

// Aplica o tema salvo (dark é o padrão) antes do primeiro render.
useThemeStore.getState().apply();

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
});

// Limpa dados de uma sessão anterior também quando o refresh expira.
useAuthStore.subscribe((state, previous) => {
  if (state.user?.id !== previous.user?.id || Boolean(state.access) !== Boolean(previous.access)) {
    queryClient.clear();
  }
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
        <Toaster />
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);
