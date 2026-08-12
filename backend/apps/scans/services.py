"""Regras de negócio do motor de scans (RN001, RN002, RN007, RN010).

Views e serializers permanecem finos; toda a lógica de criação, transição de
estado e cancelamento de scan vive aqui.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db import transaction
from django.utils import timezone

from apps.core.exceptions import Conflict

from .authorization import is_target_in_scope
from .models import FindingTriage, Scan, Target
from .profiles import normalize_options
from .validators import InvalidTarget, validate_target

logger = logging.getLogger("byakugan.scans")

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


class AuthorizationExpired(ValueError):
    """Autorização do ``Target`` referenciado já expirou (``authorization_expires_at``)."""


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
    options: dict[str, Any] | None = None,
) -> Scan:
    """Cria e persiste um scan aplicando as regras de negócio.

    Aceita um ``target_ref`` (Target cadastrado, cuja autorização é herdada) ou
    os campos ``target``/``authorized_by``/``authorization_scope`` inline. Valida
    formato do alvo (RN001), escopo de autorização (RN007), expiração da
    autorização quando aplicável e duplicidade (RN002). ``options`` (perfil de
    intensidade, portas, checks habilitados etc.) é normalizado e clampado por
    ``profiles.normalize_options`` antes de ser persistido.

    Raises:
        InvalidTarget: Alvo malformado (RN001).
        TargetOutOfScope: Alvo fora do escopo autorizado (RN007).
        AuthorizationExpired: Autorização do ``target_ref`` já expirou.
        Conflict: Já existe scan ativo para o mesmo alvo (RN002 → 409).
    """
    if target_ref is not None:
        target = target_ref.value
        authorized_by = target_ref.authorized_by
        authorization_scope = target_ref.authorization_scope
        if target_ref.authorization_expires_at and target_ref.authorization_expires_at < (
            timezone.now()
        ):
            raise AuthorizationExpired("Autorização do alvo expirou.")

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
        options=normalize_options(scan_type, options),
    )


def cancel_scan(scan: Scan) -> Scan:
    """Cancela um scan pendente/em execução (RN010).

    Além de mover o estado para ``cancelled``, tenta revogar a task Celery em
    execução (``celery_task_id``). A revogação por si só não interrompe um
    adapter já em andamento — para isso, ``tasks.run_scan`` consulta
    ``should_abort`` cooperativamente entre etapas (ver ``adapters.ScanContext``).
    """
    scan = transition(scan, Scan.Status.CANCELLED, reason="Cancelado pelo usuário.")
    if scan.celery_task_id:
        try:
            from config.celery import app as celery_app

            celery_app.control.revoke(scan.celery_task_id, terminate=False)
        except Exception:  # noqa: BLE001 — revoke é best-effort; o flip de status já ocorreu
            logger.warning("scan_revoke_failed", extra={"scan_id": str(scan.id)})
    return scan


def update_progress(scan: Scan, *, completed: int, total: int, phase: str = "") -> Scan:
    """Atualiza o progresso (0–100) e a fase corrente de um scan em execução."""
    scan.progress = min(100, int((completed / total) * 100)) if total else 0
    scan.phase = phase
    scan.save(update_fields=["progress", "phase", "updated_at"])
    return scan


def triage_finding(
    *, dedup_key: str, asset, status: str, note: str = "", updated_by=None
) -> FindingTriage:
    """Cria ou atualiza a triagem de um achado lógico (por ``dedup_key`` — Fase 5).

    Idempotente por design (``update_or_create``): triar o mesmo achado de
    novo (ex.: reclassificar de "aberto" para "risco aceito") atualiza o
    registro existente em vez de duplicar. Não audita aqui — RN011 é
    responsabilidade do caller (view), que tem acesso à requisição/IP.
    """
    triage, _ = FindingTriage.objects.update_or_create(
        dedup_key=dedup_key,
        defaults={"asset": asset, "status": status, "note": note, "updated_by": updated_by},
    )
    return triage


def delete_scan(scan: Scan) -> dict[str, int]:
    """Exclui um scan em cascata: findings, relatórios e artefatos em disco (RN014).

    As FKs ``Finding.scan`` e ``Report.scan`` permanecem ``PROTECT`` no schema —
    a cascata só acontece por este fluxo administrativo explícito e auditado,
    preservando a rede de segurança contra deleções acidentais (RN003/RN006).

    Returns:
        Contagens do que foi removido: ``{"findings": n, "reports": m}``.

    Raises:
        Conflict: Se o scan estiver ``pending``/``running`` (cancele antes — 409).
    """
    # Import tardio: apps.reports importa apps.scans; evita ciclo de módulos.
    from apps.reports.services import report_file_path

    if scan.status in ACTIVE_STATUSES:
        raise Conflict("Cancele o scan antes de excluí-lo.")

    with transaction.atomic():
        reports = list(scan.reports.all())
        for report in reports:
            report_file_path(report).unlink(missing_ok=True)
        scan.reports.all().delete()
        findings_deleted, _ = scan.findings.all().delete()
        scan.delete()

    return {"findings": findings_deleted, "reports": len(reports)}
