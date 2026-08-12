"""Helpers de teste do app reports."""

from __future__ import annotations

from apps.assets.models import Asset, Service
from apps.scans.models import Finding, Scan, Vulnerability
from apps.scans.tests.factories import ScanFactory


def make_completed_scan_with_findings() -> Scan:
    """Scan concluído com um ativo, um serviço e um finding — fixture padrão dos testes."""
    scan = ScanFactory(status=Scan.Status.COMPLETED, target="web01.example.test")
    asset = Asset.objects.create(ip="192.168.0.10", hostname="web01", os="Ubuntu 24.04")
    Service.objects.create(
        asset=asset,
        port=443,
        protocol="tcp",
        service_name="https",
        product="nginx",
        version="1.18.0",
    )

    vulnerability = Vulnerability.objects.create(
        cve="CVE-2024-1111",
        title="Vulnerabilidade de exemplo",
        severity="high",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/...",
        description="Descrição da vulnerabilidade.",
        references=["https://example.com/cve"],
    )
    Finding.objects.create(
        scan=scan,
        asset=asset,
        vulnerability=vulnerability,
        category="software",
        title="CVE-2024-1111 em nginx",
        severity="high",
        cvss=7.5,
        description="Descrição.",
        evidence="nginx 1.18.0 identificado via service (porta 443).",
        recommendation="Atualizar nginx.",
    )
    return scan
