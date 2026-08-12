"""Orquestração assíncrona de scans (Celery).

O ``run_scan`` conduz a máquina de estados (RN010), executa os adapters do tipo
de scan, normaliza e persiste os resultados, e audita o desfecho. A execução
real de varredura é gated pelo kill-switch ``BYAKUGAN_SCANNING_ENABLED``.
"""

from __future__ import annotations

import logging

from celery import shared_task
from django.conf import settings

from apps.core.audit import record_audit

from .adapters import ScanContext, get_adapters_for
from .models import Scan
from .parsers import persist_results
from .services import transition

logger = logging.getLogger("byakugan.scans")


@shared_task(name="scans.run_scan")
def run_scan(scan_id: str) -> dict:
    """Executa um scan de ponta a ponta.

    Returns:
        Resumo com contagens de ativos/serviços descobertos e o status final.
    """
    scan = Scan.objects.get(id=scan_id)

    if not settings.BYAKUGAN_SCANNING_ENABLED:
        transition(
            scan,
            Scan.Status.FAILED,
            reason="Varredura desabilitada (BYAKUGAN_SCANNING_ENABLED=False).",
        )
        record_audit(
            "scan.blocked",
            severity="warning",
            scan_id=str(scan.id),
            target=scan.target,
            reason="kill-switch",
        )
        return {"status": scan.status, "reason": "scanning_disabled"}

    transition(scan, Scan.Status.RUNNING)
    record_audit("scan.start", severity="info", scan_id=str(scan.id), target=scan.target)

    context = ScanContext(
        scan_id=str(scan.id),
        authorized_by=scan.authorized_by,
        authorization_scope=scan.authorization_scope,
    )

    try:
        raw_results = []
        for adapter in get_adapters_for(scan.scan_type):
            raw_results.extend(adapter.run(scan.target, context))
        summary = persist_results(raw_results)
    except Exception as exc:  # noqa: BLE001 — falha de scan não deve derrubar o worker
        logger.exception("scan_failed", extra={"scan_id": str(scan.id)})
        transition(scan, Scan.Status.FAILED, reason=str(exc))
        record_audit(
            "scan.failed",
            severity="critical",
            scan_id=str(scan.id),
            target=scan.target,
            error=str(exc),
        )
        return {"status": scan.status, "error": str(exc)}

    transition(scan, Scan.Status.COMPLETED)
    record_audit(
        "scan.completed",
        severity="info",
        scan_id=str(scan.id),
        target=scan.target,
        assets=summary.assets,
        services=summary.services,
        technologies=summary.technologies,
    )
    return {
        "status": scan.status,
        "assets": summary.assets,
        "services": summary.services,
        "technologies": summary.technologies,
    }
