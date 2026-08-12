"""Permission classes de RBAC (RF003, RN006).

Papéis: admin (total), analyst (cria/cancela scans, consulta), viewer (leitura).
Reaproveita o enum ``User.Role`` definido em apps/accounts/models.py.
"""

from __future__ import annotations

from rest_framework.permissions import SAFE_METHODS, BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView


def _role(request: Request) -> str | None:
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return None
    return getattr(user, "role", None)


class IsAdmin(BasePermission):
    """Permite acesso apenas a administradores."""

    message = "Requer papel de administrador."

    def has_permission(self, request: Request, view: APIView) -> bool:
        return _role(request) == "admin"


class IsAnalystOrAdmin(BasePermission):
    """Permite acesso a analistas e administradores."""

    message = "Requer papel de analista ou administrador."

    def has_permission(self, request: Request, view: APIView) -> bool:
        return _role(request) in {"analyst", "admin"}


class ReadOnlyOrAnalyst(BasePermission):
    """Leitura para qualquer autenticado; escrita só para analyst/admin.

    Exclusão (``DELETE``) exige admin (RN006).
    """

    message = "Sem permissão para esta operação."

    def has_permission(self, request: Request, view: APIView) -> bool:
        role = _role(request)
        if role is None:
            return False
        if request.method in SAFE_METHODS:
            return True
        if request.method == "DELETE":
            return role == "admin"
        return role in {"analyst", "admin"}
