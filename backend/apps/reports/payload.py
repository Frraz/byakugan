"""Construção do payload de relatório a partir de um scan (Fase 5).

Regras de composição (não de I/O pesado — os dados já vêm carregados do
banco pelo caller). Reaproveita o Correlation Engine (`apps.scans.correlation`)
para o risk score e o heatmap, mantendo a mesma fórmula usada no dashboard
(ver docs/scanning-engine.md).
"""

from __future__ import annotations

from typing import Any

from django.utils import timezone

from apps.assets.models import Asset
from apps.scans.correlation import compute_asset_risk, compute_heatmap, compute_risk
from apps.scans.models import Finding, Scan

from .models import Report

TOP_RISKS_LIMIT = 5


def _asset_label(asset: Asset) -> str:
    """Rótulo de exibição de um ativo — ex.: ``web-01 (192.168.0.10)``."""
    name = asset.hostname or asset.domain
    if name and asset.ip:
        return f"{name} ({asset.ip})"
    return name or asset.ip or str(asset.id)


def build_summary(scan: Scan) -> dict[str, Any]:
    """Resumo do scan: ativos analisados, distribuição de severidade e risco."""
    rows = list(scan.findings.values("asset_id", "severity", "cvss"))
    risk = compute_risk(rows)
    assets = len({r["asset_id"] for r in rows})
    return {
        "assets": assets,
        "severity": risk.severity,
        "risk_score": risk.risk_score,
        "risk_level": risk.risk_level,
    }


def build_top_risks(scan: Scan, limit: int = TOP_RISKS_LIMIT) -> list[dict[str, Any]]:
    """Ativos priorizados por risk_score (Correlation Engine)."""
    rows = list(
        scan.findings.values(
            "asset_id", "asset__ip", "asset__hostname", "asset__domain", "severity", "cvss"
        )
    )
    return compute_asset_risk(rows)[:limit]


def build_findings_section(scan: Scan) -> list[dict[str, Any]]:
    """Lista completa de findings do scan, com evidência e recomendação (RN008)."""
    findings: list[Finding] = list(
        scan.findings.select_related("asset", "vulnerability").order_by("-cvss")
    )
    return [
        {
            "asset": _asset_label(f.asset),
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "cvss": float(f.cvss) if f.cvss is not None else None,
            "cve": f.vulnerability.cve if f.vulnerability else None,
            "description": f.description,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]


def build_asset_inventory(scan: Scan) -> list[dict[str, Any]]:
    """Inventário de ativos/serviços cobertos pelo scan (relatório técnico)."""
    asset_ids = scan.findings.values_list("asset_id", flat=True).distinct()
    assets = Asset.objects.filter(id__in=asset_ids).prefetch_related("services")
    return [
        {
            "asset": _asset_label(asset),
            "os": asset.os,
            "services": [f"{s.port}/{s.protocol} {s.service_name}" for s in asset.services.all()],
        }
        for asset in assets
    ]


def build_scan_metadata(scan: Scan) -> dict[str, Any]:
    """Metadados de execução do scan (relatório técnico)."""
    return {
        "scan_type": scan.scan_type,
        "status": scan.status,
        "authorized_by": scan.authorized_by,
        "authorization_scope": scan.authorization_scope,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }


def build_report_payload(scan: Scan, report_type: str) -> dict[str, Any]:
    """Monta o payload completo do relatório (estrutura de docs/reporting.md).

    O relatório **executivo** foca em risco de negócio: resumo, top riscos
    priorizados e heatmap por categoria. O **técnico** traz o inventário de
    ativos e a lista completa de findings com evidência/recomendação.
    """
    payload: dict[str, Any] = {
        "scan_id": str(scan.id),
        "generated_at": timezone.now().isoformat(),
        "target": scan.target,
        "report_type": report_type,
        "summary": build_summary(scan),
    }

    if report_type == Report.ReportType.EXECUTIVE:
        payload["top_risks"] = build_top_risks(scan)
        payload["heatmap"] = compute_heatmap(list(scan.findings.values("category", "severity")))
    else:
        payload["scan"] = build_scan_metadata(scan)
        payload["assets"] = build_asset_inventory(scan)
        payload["findings"] = build_findings_section(scan)

    return payload
