"""Testes de integração da API de Targets e Scans (RBAC, RN002, RN007, RN014)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.core.models import AuditLog
from apps.scans.models import Finding, Scan
from apps.scans.tests.factories import ScanFactory, TargetFactory

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _no_enqueue(monkeypatch):
    """Evita enfileirar de verdade — isola a camada HTTP do worker."""
    monkeypatch.setattr("apps.scans.views.run_scan.delay", lambda *a, **k: None)


# --- Targets ---


def test_analyst_can_create_target(analyst_client):
    resp = analyst_client.post(
        reverse("scans:target-list"),
        {
            "name": "DMZ",
            "value": "192.168.10.0/24",
            "authorized_by": "CISO",
            "authorization_scope": "192.168.10.0/24",
        },
        format="json",
    )
    assert resp.status_code == 201
    assert resp.data["kind"] == "cidr"


def test_viewer_cannot_create_target(viewer_client):
    resp = viewer_client.post(
        reverse("scans:target-list"),
        {
            "name": "x",
            "value": "empresa.com",
            "authorized_by": "a",
            "authorization_scope": "empresa.com",
        },
        format="json",
    )
    assert resp.status_code == 403


def test_create_target_rejects_invalid_value(analyst_client):
    resp = analyst_client.post(
        reverse("scans:target-list"),
        {"name": "x", "value": "not a host", "authorized_by": "a", "authorization_scope": "x"},
        format="json",
    )
    assert resp.status_code == 400


def test_only_admin_can_delete_target(analyst_client, admin_client):
    target = TargetFactory()
    url = reverse("scans:target-detail", args=[target.id])
    assert analyst_client.delete(url).status_code == 403
    assert admin_client.delete(url).status_code == 204


def test_patch_target_recalculates_kind_and_audits(analyst_client):
    target = TargetFactory(value="empresa.com", kind="domain", authorization_scope="empresa.com")
    resp = analyst_client.patch(
        reverse("scans:target-detail", args=[target.id]),
        {"value": "10.0.0.0/24"},
        format="json",
    )
    assert resp.status_code == 200
    assert resp.data["kind"] == "cidr"
    assert AuditLog.objects.filter(action="target.update").exists()


def test_target_list_exposes_scans_count(viewer_client):
    target = TargetFactory()
    ScanFactory(target_ref=target)
    ScanFactory(target_ref=target)
    resp = viewer_client.get(reverse("scans:target-list"))
    assert resp.status_code == 200
    row = next(r for r in resp.data["results"] if r["id"] == str(target.id))
    assert row["scans_count"] == 2


def test_delete_target_preserves_scans(admin_client):
    target = TargetFactory()
    scan = ScanFactory(target_ref=target, status=Scan.Status.COMPLETED)
    resp = admin_client.delete(reverse("scans:target-detail", args=[target.id]))
    assert resp.status_code == 204
    scan.refresh_from_db()
    assert scan.target_ref is None


# --- Scans ---


def test_analyst_creates_scan_inline(analyst_client):
    resp = analyst_client.post(
        reverse("scans:scan-list"),
        {
            "scan_type": "discovery",
            "target": "empresa.com",
            "authorized_by": "CISO",
            "authorization_scope": "empresa.com",
        },
        format="json",
    )
    assert resp.status_code == 201
    assert resp.data["status"] == "pending"


def test_create_scan_via_target_ref(analyst_client):
    target = TargetFactory(value="empresa.com", authorization_scope="empresa.com")
    resp = analyst_client.post(
        reverse("scans:scan-list"),
        {"scan_type": "discovery", "target_ref": str(target.id)},
        format="json",
    )
    assert resp.status_code == 201
    assert resp.data["target"] == "empresa.com"


def test_viewer_cannot_create_scan(viewer_client):
    resp = viewer_client.post(
        reverse("scans:scan-list"),
        {
            "scan_type": "discovery",
            "target": "empresa.com",
            "authorized_by": "a",
            "authorization_scope": "empresa.com",
        },
        format="json",
    )
    assert resp.status_code == 403


def test_rn007_out_of_scope_returns_403(analyst_client):
    resp = analyst_client.post(
        reverse("scans:scan-list"),
        {
            "scan_type": "discovery",
            "target": "evil.com",
            "authorized_by": "a",
            "authorization_scope": "empresa.com",
        },
        format="json",
    )
    assert resp.status_code == 403


def test_rn002_duplicate_scan_returns_409(analyst_client, analyst_user):
    ScanFactory(target="empresa.com", status=Scan.Status.RUNNING, authorization_scope="empresa.com")
    resp = analyst_client.post(
        reverse("scans:scan-list"),
        {
            "scan_type": "discovery",
            "target": "empresa.com",
            "authorized_by": "a",
            "authorization_scope": "empresa.com",
        },
        format="json",
    )
    assert resp.status_code == 409


def test_cancel_scan(analyst_client):
    scan = ScanFactory(status=Scan.Status.PENDING)
    resp = analyst_client.post(reverse("scans:scan-cancel", args=[scan.id]))
    assert resp.status_code == 200
    assert resp.data["status"] == "cancelled"


def test_scan_list_includes_findings_summary(viewer_client):
    from apps.reports.tests.factories import make_completed_scan_with_findings

    scan = make_completed_scan_with_findings()
    resp = viewer_client.get(reverse("scans:scan-list"))
    assert resp.status_code == 200
    row = next(r for r in resp.data["results"] if r["id"] == str(scan.id))
    assert row["findings_count"] == 1
    assert row["severity_counts"]["high"] == 1
    assert row["severity_counts"]["critical"] == 0
    assert row["target_name"] is None  # scan inline, sem target cadastrado


def test_scan_list_includes_target_name(viewer_client):
    target = TargetFactory(name="DMZ Lab")
    ScanFactory(target_ref=target)
    resp = viewer_client.get(reverse("scans:scan-list"))
    assert resp.data["results"][0]["target_name"] == "DMZ Lab"


# --- Scan delete (RN014) ---


def test_admin_deletes_scan_cascading_findings_and_reports(
    admin_client, admin_user, settings, tmp_path
):
    from apps.reports.models import Report
    from apps.reports.services import generate_report, report_file_path
    from apps.reports.tests.factories import make_completed_scan_with_findings

    settings.MEDIA_ROOT = str(tmp_path)
    scan = make_completed_scan_with_findings()
    report = generate_report(
        scan=scan, report_type="technical", format="json", created_by=admin_user
    )
    artifact = report_file_path(report)
    assert artifact.exists()

    resp = admin_client.delete(reverse("scans:scan-detail", args=[scan.id]))

    assert resp.status_code == 204
    assert not Scan.objects.filter(id=scan.id).exists()
    assert not Finding.objects.filter(scan_id=scan.id).exists()
    assert not Report.objects.filter(scan_id=scan.id).exists()
    assert not artifact.exists()
    log = AuditLog.objects.get(action="scan.delete")
    assert log.metadata["findings_deleted"] == 1
    assert log.metadata["reports_deleted"] == 1


@pytest.mark.parametrize("status_", [Scan.Status.PENDING, Scan.Status.RUNNING])
def test_delete_active_scan_returns_409(admin_client, status_):
    scan = ScanFactory(status=status_)
    resp = admin_client.delete(reverse("scans:scan-detail", args=[scan.id]))
    assert resp.status_code == 409
    assert Scan.objects.filter(id=scan.id).exists()


def test_analyst_cannot_delete_scan(analyst_client):
    scan = ScanFactory(status=Scan.Status.COMPLETED)
    resp = analyst_client.delete(reverse("scans:scan-detail", args=[scan.id]))
    assert resp.status_code == 403


# --- Scan services endpoint (discovery sem findings) ---


def test_scan_services_returns_discovered_services_without_findings(viewer_client):
    """Scan de discovery não gera findings, mas seus serviços devem aparecer."""
    from apps.assets.models import Asset, Service

    asset = Asset.objects.create(ip="203.0.113.10", hostname="host", os="Linux")
    Service.objects.create(asset=asset, port=443, protocol="tcp", service_name="https")
    Service.objects.create(asset=asset, port=22, protocol="tcp", service_name="ssh")
    scan = ScanFactory(target="203.0.113.10", status=Scan.Status.COMPLETED)

    resp = viewer_client.get(reverse("scans:scan-services", args=[scan.id]))

    assert resp.status_code == 200
    assert {row["port"] for row in resp.data} == {443, 22}


def test_scan_services_matches_domain_target_without_inet_error(viewer_client):
    """Alvo não-IP (domínio) não pode quebrar o filtro do campo inet (Postgres)."""
    from apps.assets.models import Asset, Service

    asset = Asset.objects.create(hostname="empresa.com", domain="empresa.com")
    Service.objects.create(asset=asset, port=80, protocol="tcp", service_name="http")
    scan = ScanFactory(target="empresa.com", status=Scan.Status.COMPLETED)

    resp = viewer_client.get(reverse("scans:scan-services", args=[scan.id]))

    assert resp.status_code == 200
    assert [row["port"] for row in resp.data] == [80]
