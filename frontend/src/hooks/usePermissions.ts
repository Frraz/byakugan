/** Permissões derivadas do papel do usuário (RBAC — RN006). */

import { useAuthStore } from "@/store/auth";

export interface Permissions {
  role: string | undefined;
  /** Pode criar/editar (analyst ou admin). */
  canWrite: boolean;
  /** Pode excluir registros (apenas admin — RN006). */
  isAdmin: boolean;
}

export function usePermissions(): Permissions {
  // Espelha ReadOnlyOrAnalyst/IsAdmin. O backend revalida toda operação.
  const user = useAuthStore((s) => s.user);
  return {
    role: user?.role,
    canWrite: user?.role === "admin" || user?.role === "analyst",
    isAdmin: user?.role === "admin",
  };
}
