"""Serviço de auditoria (RNF007, RN011).

``record_audit`` persiste o evento na trilha imutável (``AuditLog``) e emite
um log estruturado JSON. Deve ser chamado em todo evento sensível: login,
logout, criação/cancelamento de scan, exportação de relatório, exclusões e
mudanças de permissão.
"""

from __future__ import annotations

import logging
from typing import Any

from rest_framework.request import Request

from .models import AuditLog

logger = logging.getLogger("byakugan.audit")


def client_ip(request: Request) -> str | None:
    """Extrai o IP de origem da requisição (respeitando proxy reverso)."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def record_audit(
    action: str,
    *,
    user: Any | None = None,
    user_email: str | None = None,
    severity: str = AuditLog.Severity.INFO,
    source: str | None = None,
    **metadata: Any,
) -> AuditLog:
    """Registra um evento de auditoria.

    Args:
        action: Identificador do evento (ex.: ``scan.create``).
        user: Instância de usuário autor do evento (opcional).
        user_email: Email quando o usuário ainda não está resolvido (ex.: login).
        severity: ``info`` | ``warning`` | ``critical``.
        source: IP/origem do evento.
        **metadata: Detalhes adicionais serializáveis em JSON.

    Returns:
        O ``AuditLog`` persistido.
    """
    resolved_user = (
        user if (user is not None and getattr(user, "is_authenticated", False)) else None
    )
    if user_email and "user_email" not in metadata:
        metadata["user_email"] = user_email

    entry = AuditLog.objects.create(
        user=resolved_user,
        action=action,
        severity=severity,
        source=source,
        metadata=metadata,
    )
    logger.info(
        "audit",
        extra={
            "action": action,
            "severity": severity,
            "source": source,
            "user_id": str(resolved_user.id) if resolved_user else None,
            "metadata": metadata,
        },
    )
    return entry
