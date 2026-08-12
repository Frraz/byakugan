"""Testes de integração da API global de Vulnerabilities e Findings (RF008)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.assets.models import Asset
from apps.core.models import AuditLog
from apps.scans.models import Finding, FindingTriage, Vulnerability
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


def test_finding_payload_nests_vulnerability_asset_and_scan(
    viewer_client, finding_with_vulnerability
):
    resp = viewer_client.get(reverse("scans:finding-list"))
    row = resp.data["results"][0]
    assert row["vulnerability"]["cve"] == "CVE-2024-1111"
    assert row["vulnerability"]["references"] == ["https://example.com/cve"]
    assert row["asset"]["hostname"] == "web01"
    assert row["asset"]["ip"] == "192.168.0.10"
    assert row["scan"]["id"] == str(finding_with_vulnerability.scan_id)
    assert row["scan"]["target"] == finding_with_vulnerability.scan.target


def test_filter_findings_by_category(viewer_client, finding_with_vulnerability):
    assert (
        viewer_client.get(reverse("scans:finding-list"), {"category": "software"}).data["count"]
        == 1
    )
    assert (
        viewer_client.get(reverse("scans:finding-list"), {"category": "network"}).data["count"] == 0
    )


def test_search_findings_by_title_and_cve(viewer_client, finding_with_vulnerability):
    assert viewer_client.get(reverse("scans:finding-list"), {"search": "nginx"}).data["count"] == 1
    assert (
        viewer_client.get(reverse("scans:finding-list"), {"search": "CVE-2024-1111"}).data["count"]
        == 1
    )
    assert viewer_client.get(reverse("scans:finding-list"), {"search": "xyz"}).data["count"] == 0


def test_finding_defaults_to_open_triage_status(viewer_client, finding_with_vulnerability):
    resp = viewer_client.get(reverse("scans:finding-list"))
    assert resp.data["results"][0]["triage_status"] == "open"
    assert resp.data["results"][0]["dedup_key"] == finding_with_vulnerability.dedup_key


# --- Triage (Fase 5) ---


def _triage_url(finding):
    return reverse("scans:finding-triage", args=[finding.id])


def test_triage_requires_auth(api_client, finding_with_vulnerability):
    resp = api_client.post(_triage_url(finding_with_vulnerability), {"status": "fixed"})
    assert resp.status_code == 401


def test_viewer_cannot_triage(viewer_client, finding_with_vulnerability):
    resp = viewer_client.post(_triage_url(finding_with_vulnerability), {"status": "fixed"})
    assert resp.status_code == 403
    assert not FindingTriage.objects.exists()


def test_analyst_can_triage_finding(analyst_client, finding_with_vulnerability):
    resp = analyst_client.post(
        _triage_url(finding_with_vulnerability),
        {"status": "false-positive", "note": "Confirmado falso positivo."},
    )
    assert resp.status_code == 200
    assert resp.data["status"] == "false-positive"
    assert resp.data["note"] == "Confirmado falso positivo."
    assert resp.data["dedup_key"] == finding_with_vulnerability.dedup_key

    triage = FindingTriage.objects.get(dedup_key=finding_with_vulnerability.dedup_key)
    assert triage.status == "false-positive"
    assert triage.asset_id == finding_with_vulnerability.asset_id


def test_admin_can_triage_finding(admin_client, finding_with_vulnerability):
    resp = admin_client.post(_triage_url(finding_with_vulnerability), {"status": "fixed"})
    assert resp.status_code == 200


def test_triage_rejects_invalid_status(analyst_client, finding_with_vulnerability):
    resp = analyst_client.post(_triage_url(finding_with_vulnerability), {"status": "bogus"})
    assert resp.status_code == 400
    assert not FindingTriage.objects.exists()


def test_triage_records_audit_event(analyst_client, finding_with_vulnerability):
    analyst_client.post(_triage_url(finding_with_vulnerability), {"status": "accepted-risk"})
    log = AuditLog.objects.get(action="finding.triage")
    assert log.metadata["finding_id"] == str(finding_with_vulnerability.id)
    assert log.metadata["dedup_key"] == finding_with_vulnerability.dedup_key
    assert log.metadata["status"] == "accepted-risk"


def test_triage_is_idempotent_across_calls(analyst_client, finding_with_vulnerability):
    analyst_client.post(_triage_url(finding_with_vulnerability), {"status": "fixed"})
    analyst_client.post(_triage_url(finding_with_vulnerability), {"status": "open"})

    assert FindingTriage.objects.count() == 1
    assert FindingTriage.objects.get().status == "open"


def test_triage_reflects_in_finding_list_triage_status(analyst_client, finding_with_vulnerability):
    analyst_client.post(_triage_url(finding_with_vulnerability), {"status": "fixed"})

    resp = analyst_client.get(reverse("scans:finding-list"))
    assert resp.data["results"][0]["triage_status"] == "fixed"
