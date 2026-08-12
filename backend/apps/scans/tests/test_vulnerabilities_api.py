"""Testes de integração da API global de Vulnerabilities e Findings (RF008)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.assets.models import Asset
from apps.scans.models import Finding, Vulnerability
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


@pytest.fixture
def finding_with_vulnerability(db):
    asset = Asset.objects.create(ip="192.168.0.10", hostname="web01")
    scan = ScanFactory()
    vulnerability = Vulnerability.objects.create(
        cve="CVE-2024-1111",
        title="Vulnerabilidade de exemplo",
        severity="high",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/...",
        description="Descrição.",
        references=["https://example.com/cve"],
    )
    finding = Finding.objects.create(
        scan=scan,
        asset=asset,
        vulnerability=vulnerability,
        category="software",
        title="CVE-2024-1111 em nginx",
        severity="high",
        cvss=7.5,
        description="Descrição.",
        evidence="evidência",
        recommendation="recomendação",
    )
    return finding


# --- Vulnerabilities ---


def test_list_vulnerabilities_requires_auth(api_client):
    assert api_client.get(reverse("scans:vulnerability-list")).status_code == 401


def test_viewer_can_list_vulnerabilities(viewer_client, finding_with_vulnerability):
    resp = viewer_client.get(reverse("scans:vulnerability-list"))
    assert resp.status_code == 200
    assert resp.data["count"] == 1
    assert resp.data["results"][0]["cve"] == "CVE-2024-1111"


def test_filter_vulnerabilities_by_severity(viewer_client, finding_with_vulnerability):
    resp = viewer_client.get(reverse("scans:vulnerability-list"), {"severity": "critical"})
    assert resp.status_code == 200
    assert resp.data["count"] == 0


def test_search_vulnerabilities_by_cve(viewer_client, finding_with_vulnerability):
    resp = viewer_client.get(reverse("scans:vulnerability-list"), {"search": "2024-1111"})
    assert resp.status_code == 200
    assert resp.data["count"] == 1


# --- Findings ---


def test_list_findings_requires_auth(api_client):
    assert api_client.get(reverse("scans:finding-list")).status_code == 401


def test_viewer_can_list_findings(viewer_client, finding_with_vulnerability):
    resp = viewer_client.get(reverse("scans:finding-list"))
    assert resp.status_code == 200
    assert resp.data["count"] == 1
    assert resp.data["results"][0]["vulnerability"] is not None


def test_filter_findings_by_asset(viewer_client, finding_with_vulnerability):
    resp = viewer_client.get(
        reverse("scans:finding-list"), {"asset": str(finding_with_vulnerability.asset_id)}
    )
    assert resp.status_code == 200
    assert resp.data["count"] == 1


def test_filter_findings_by_scan(viewer_client, finding_with_vulnerability):
    resp = viewer_client.get(
        reverse("scans:finding-list"), {"scan": str(finding_with_vulnerability.scan_id)}
    )
    assert resp.status_code == 200
    assert resp.data["count"] == 1


def test_filter_findings_by_severity_excludes_mismatch(viewer_client, finding_with_vulnerability):
    resp = viewer_client.get(reverse("scans:finding-list"), {"severity": "low"})
    assert resp.status_code == 200
    assert resp.data["count"] == 0
