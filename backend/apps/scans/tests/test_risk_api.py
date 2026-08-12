"""Testes de integração da API de Correlation Engine (GET /api/risk/overview/)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.assets.models import Asset
from apps.scans.models import Finding, FindingTriage, Vulnerability
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


def _finding(
    asset,
    scan,
    *,
    severity="high",
    cvss=7.5,
    category="software",
    cve="CVE-2024-0001",
    dedup_key="",
):
    vulnerability = Vulnerability.objects.create(
        cve=cve, title=f"{cve}", severity=severity, cvss_score=cvss, description="d"
    )
    return Finding.objects.create(
        scan=scan,
        asset=asset,
        vulnerability=vulnerability,
        category=category,
        title=f"{cve} em {asset}",
        severity=severity,
        cvss=cvss,
        description="d",
        evidence="e",
        recommendation="r",
        dedup_key=dedup_key,
    )


def test_risk_overview_requires_auth(api_client):
    assert api_client.get(reverse("scans:risk-overview")).status_code == 401


def test_risk_overview_with_no_findings(viewer_client):
    Asset.objects.create(ip="192.168.0.10")
    resp = viewer_client.get(reverse("scans:risk-overview"))
    assert resp.status_code == 200
    assert resp.data["summary"]["assets"] == 1
    assert resp.data["summary"]["findings"] == 0
    assert resp.data["summary"]["risk_score"] == 0
    assert resp.data["summary"]["risk_level"] == "info"
    assert resp.data["top_assets"] == []
    assert resp.data["heatmap"] == []


def test_risk_overview_prioritizes_riskiest_asset_first(viewer_client):
    scan = ScanFactory()
    low_asset = Asset.objects.create(ip="192.168.0.10", hostname="low")
    high_asset = Asset.objects.create(ip="192.168.0.20", hostname="high")
    _finding(low_asset, scan, severity="low", cvss=2.0, cve="CVE-2024-LOW")
    for i in range(10):  # acumula CVSS suficiente para cruzar a banda "critical" (>=90)
        _finding(high_asset, scan, severity="critical", cvss=9.8, cve=f"CVE-2024-C{i}")

    resp = viewer_client.get(reverse("scans:risk-overview"))

    assert resp.status_code == 200
    top_assets = resp.data["top_assets"]
    assert top_assets[0]["hostname"] == "high"
    assert top_assets[0]["risk_score"] > top_assets[1]["risk_score"]
    assert top_assets[0]["risk_level"] == "critical"
    assert resp.data["summary"]["severity"]["critical"] == 10
    assert resp.data["summary"]["severity"]["low"] == 1


def test_risk_overview_limit_param(viewer_client):
    scan = ScanFactory()
    for i in range(3):
        asset = Asset.objects.create(ip=f"192.168.0.{i}", hostname=f"host{i}")
        _finding(asset, scan, cve=f"CVE-2024-000{i}")

    resp = viewer_client.get(reverse("scans:risk-overview"), {"limit": 2})
    assert len(resp.data["top_assets"]) == 2


def test_risk_overview_heatmap_groups_by_category(viewer_client):
    scan = ScanFactory()
    asset = Asset.objects.create(ip="192.168.0.10")
    _finding(asset, scan, category="tls", severity="medium", cve="CVE-2024-1000")
    _finding(asset, scan, category="tls", severity="medium", cve="CVE-2024-1001")

    resp = viewer_client.get(reverse("scans:risk-overview"))

    assert len(resp.data["heatmap"]) == 1
    cell = resp.data["heatmap"][0]
    assert cell["category"] == "tls"
    assert cell["severity"] == "medium"
    assert cell["count"] == 2
    assert cell["category_label"] == "TLS"


# --- Triagem exclui achados resolvidos da soma do risk_score (Fase 5) --------


def test_risk_overview_excludes_resolved_triage_from_score(viewer_client):
    scan = ScanFactory()
    asset = Asset.objects.create(ip="192.168.0.10")
    _finding(asset, scan, severity="high", cvss=7.5, cve="CVE-2024-2000", dedup_key="dk-1")

    resp_before = viewer_client.get(reverse("scans:risk-overview"))
    assert resp_before.data["summary"]["findings"] == 1
    assert resp_before.data["summary"]["risk_score"] > 0

    FindingTriage.objects.create(dedup_key="dk-1", asset=asset, status="false-positive")

    resp_after = viewer_client.get(reverse("scans:risk-overview"))
    assert resp_after.data["summary"]["findings"] == 0
    assert resp_after.data["summary"]["risk_score"] == 0
    assert resp_after.data["top_assets"] == []
    assert resp_after.data["heatmap"] == []


def test_risk_overview_keeps_open_triage_in_score(viewer_client):
    scan = ScanFactory()
    asset = Asset.objects.create(ip="192.168.0.10")
    _finding(asset, scan, severity="high", cvss=7.5, cve="CVE-2024-2001", dedup_key="dk-2")
    FindingTriage.objects.create(dedup_key="dk-2", asset=asset, status="open")

    resp = viewer_client.get(reverse("scans:risk-overview"))
    assert resp.data["summary"]["findings"] == 1
    assert resp.data["summary"]["risk_score"] > 0


def test_risk_overview_reruns_only_inflate_score_until_triaged(viewer_client):
    """Reproduz o bug do score aditivo: 3 reexecuções somam 3x até a triagem excluir."""
    scan1, scan2, scan3 = ScanFactory(), ScanFactory(), ScanFactory()
    asset = Asset.objects.create(ip="192.168.0.10")
    for scan in (scan1, scan2, scan3):
        _finding(asset, scan, severity="high", cvss=7.5, cve="CVE-2024-2002", dedup_key="dk-3")

    resp_before = viewer_client.get(reverse("scans:risk-overview"))
    assert resp_before.data["summary"]["findings"] == 3

    FindingTriage.objects.create(dedup_key="dk-3", asset=asset, status="fixed")

    resp_after = viewer_client.get(reverse("scans:risk-overview"))
    assert resp_after.data["summary"]["findings"] == 0
    assert resp_after.data["summary"]["risk_score"] == 0


def test_risk_overview_excludes_only_the_triaged_dedup_key(viewer_client):
    scan = ScanFactory()
    asset = Asset.objects.create(ip="192.168.0.10")
    _finding(asset, scan, severity="high", cvss=7.5, cve="CVE-2024-2003", dedup_key="dk-fixed")
    _finding(asset, scan, severity="medium", cvss=5.0, cve="CVE-2024-2004", dedup_key="dk-open")
    FindingTriage.objects.create(dedup_key="dk-fixed", asset=asset, status="accepted-risk")

    resp = viewer_client.get(reverse("scans:risk-overview"))
    assert resp.data["summary"]["findings"] == 1
    assert resp.data["summary"]["severity"]["medium"] == 1
    assert resp.data["summary"]["severity"]["high"] == 0
