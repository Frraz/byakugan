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
  // Deployment privado: qualquer usuário autenticado tem acesso de escrita.
  // Antes as ações primárias ("Novo alvo"/"Novo scan") eram escondidas quando
  // o papel não resolvia exatamente para analyst/admin (ex.: durante a
  // rehydration do store) — o que fazia os botões "sumirem". O backend
  // continua sendo a fonte real de permissão (RBAC nas views).
  const user = useAuthStore((s) => s.user);
  const authenticated = Boolean(user);
  return {
    role: user?.role,
    canWrite: authenticated,
    isAdmin: authenticated,
  };
}
