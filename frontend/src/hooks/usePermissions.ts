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
  const role = useAuthStore((s) => s.user?.role);
  return {
    role,
    canWrite: role === "analyst" || role === "admin",
    isAdmin: role === "admin",
  };
}
