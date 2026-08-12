/** Protege rotas: redireciona para /login sem sessão ativa. */

import { Navigate, Outlet } from "react-router-dom";

import { useAuthStore } from "../store/auth";

export function ProtectedRoute() {
  const access = useAuthStore((s) => s.access);
  return access ? <Outlet /> : <Navigate to="/login" replace />;
}
