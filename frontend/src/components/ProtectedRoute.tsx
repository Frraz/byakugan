/** Protege rotas: redireciona para /login sem sessão ativa. */

import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAuthStore } from "../store/auth";

export function ProtectedRoute() {
  const access = useAuthStore((s) => s.access);
  const location = useLocation();
  return access ? <Outlet /> : <Navigate to="/login" state={{ from: location.pathname + location.search }} replace />;
}
