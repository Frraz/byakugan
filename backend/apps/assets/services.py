"""Regras de negócio do inventário de ativos (RN020)."""

from __future__ import annotations

from django.db import transaction

from .models import Asset


def delete_asset(asset: Asset) -> dict[str, int]:
    """Exclui um ativo em cascata (RN020).

    ``Finding.asset`` permanece ``PROTECT`` no schema (rede de segurança
    contra deleções acidentais — mesmo racional de ``Finding.scan``/
    ``Report.scan`` em ``scans.services.delete_scan``); a cascata só
    acontece por este fluxo administrativo explícito e auditado.
    ``Service``/``Technology``/``DnsRecord``/``FindingTriage`` já são
    ``CASCADE`` no schema e são removidos automaticamente por ``asset.delete()``.

    Returns:
        Contagens do que foi removido: ``{"findings": n}``.
    """
    with transaction.atomic():
        findings_deleted, _ = asset.findings.all().delete()
        asset.delete()

    return {"findings": findings_deleted}
