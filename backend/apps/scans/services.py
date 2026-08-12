"""Regras de negócio do motor de scans (RN001, RN002, RN007, RN010).

Views e serializers permanecem finos; toda a lógica de criação, transição de
estado e cancelamento de scan vive aqui.
"""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from apps.core.exceptions import Conflict

from .authorization import is_target_in_scope
from .models import Scan, Target
from .validators import InvalidTarget, validate_target

# Máquina de estados permitida (RN010).
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    Scan.Status.PENDING: {Scan.Status.RUNNING, Scan.Status.CANCELLED, Scan.Status.FAILED},
    Scan.Status.RUNNING: {Scan.Status.COMPLETED, Scan.Status.FAILED, Scan.Status.CANCELLED},
    Scan.Status.COMPLETED: set(),
    Scan.Status.FAILED: set(),
    Scan.Status.CANCELLED: set(),
}

ACTIVE_STATUSES = {Scan.Status.PENDING, Scan.Status.RUNNING}


class InvalidTransition(ValueError):
    """Transição de estado não permitida pela máquina de estados (RN010)."""


class TargetOutOfScope(ValueError):
    """Alvo fora do escopo autorizado (RN007)."""


def transition(scan: Scan, new_status: str, *, reason: str = "") -> Scan:
    """Aplica uma transição de estado validando a máquina de estados (RN010).

    Raises:
        InvalidTransition: Se a transição não for permitida.
    """
    if new_status not in ALLOWED_TRANSITIONS.get(scan.status, set()):
        raise InvalidTransition(f"Transição inválida: {scan.status} → {new_status}.")

    scan.status = new_status
    if new_status == Scan.Status.RUNNING and scan.started_at is None:
        scan.started_at = timezone.now()
    if new_status in {Scan.Status.COMPLETED, Scan.Status.FAILED, Scan.Status.CANCELLED}:
        scan.finished_at = timezone.now()
    if reason:
        scan.failure_reason = reason
    scan.save(update_fields=["status", "started_at", "finished_at", "failure_reason", "updated_at"])
    return scan


@transaction.atomic
def create_scan(
    *,
    created_by,
    scan_type: str,
    target: str | None = None,
    authorized_by: str | None = None,
    authorization_scope: str | None = None,
    target_ref: Target | None = None,
) -> Scan:
    """Cria e persiste um scan aplicando as regras de negócio.

    Aceita um ``target_ref`` (Target cadastrado, cuja autorização é herdada) ou
    os campos ``target``/``authorized_by``/``authorization_scope`` inline. Valida
    formato do alvo (RN001), escopo de autorização (RN007) e duplicidade (RN002).

    Raises:
        InvalidTarget: Alvo malformado (RN001).
        TargetOutOfScope: Alvo fora do escopo autorizado (RN007).
        Conflict: Já existe scan ativo para o mesmo alvo (RN002 → 409).
    """
    if target_ref is not None:
        target = target_ref.value
        authorized_by = target_ref.authorized_by
        authorization_scope = target_ref.authorization_scope

    if not target:
        raise InvalidTarget("Alvo é obrigatório.")
    if not authorized_by or not authorization_scope:
        raise TargetOutOfScope("Autorização (authorized_by + escopo) é obrigatória.")

    target = validate_target(target)  # RN001

    if not is_target_in_scope(target, authorization_scope):  # RN007
        raise TargetOutOfScope("Alvo fora do escopo autorizado.")

    duplicate = Scan.objects.filter(target=target, status__in=ACTIVE_STATUSES).exists()
    if duplicate:  # RN002
        raise Conflict("Já existe um scan em execução para este alvo.")

    return Scan.objects.create(
        created_by=created_by,
        target_ref=target_ref,
        target=target,
        scan_type=scan_type,
        authorized_by=authorized_by,
        authorization_scope=authorization_scope,
        status=Scan.Status.PENDING,
    )


def cancel_scan(scan: Scan) -> Scan:
    """Cancela um scan pendente/em execução (RN010)."""
    return transition(scan, Scan.Status.CANCELLED, reason="Cancelado pelo usuário.")
