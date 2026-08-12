"""Testes de integração da API de Reports (RF009, RF010, RN012)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.reports.models import Report
from apps.reports.tests.factories import make_completed_scan_with_findings
from apps.scans.models import Scan
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


def test_create_report_requires_auth(api_client):
    resp = api_client.post(reverse("reports:report-list"), {}, format="json")
    assert resp.status_code == 401


def test_viewer_cannot_create_report(viewer_client):
    scan = make_completed_scan_with_findings()
    resp = viewer_client.post(
        reverse("reports:report-list"),
        {"scan": str(scan.id), "report_type": "executive", "format": "json"},
        format="json",
    )
    assert resp.status_code == 403


def test_analyst_generates_json_report(analyst_client):
    scan = make_completed_scan_with_findings()
    resp = analyst_client.post(
        reverse("reports:report-list"),
        {"scan": str(scan.id), "report_type": "executive", "format": "json"},
        format="json",
    )
    assert resp.status_code == 201
    assert resp.data["report_type"] == "executive"
    assert resp.data["format"] == "json"
    assert Report.objects.count() == 1


def test_rn012_rejects_report_for_non_completed_scan(analyst_client):
    scan = ScanFactory(status=Scan.Status.PENDING)
    resp = analyst_client.post(
        reverse("reports:report-list"),
        {"scan": str(scan.id), "report_type": "technical", "format": "pdf"},
        format="json",
    )
    assert resp.status_code == 409


def test_viewer_can_list_reports(viewer_client, analyst_client):
    scan = make_completed_scan_with_findings()
    analyst_client.post(
        reverse("reports:report-list"),
        {"scan": str(scan.id), "report_type": "executive", "format": "json"},
        format="json",
    )
    resp = viewer_client.get(reverse("reports:report-list"))
    assert resp.status_code == 200
    assert resp.data["count"] == 1


def test_download_report(analyst_client):
    scan = make_completed_scan_with_findings()
    create_resp = analyst_client.post(
        reverse("reports:report-list"),
        {"scan": str(scan.id), "report_type": "technical", "format": "pdf"},
        format="json",
    )
    report_id = create_resp.data["id"]

    resp = analyst_client.get(reverse("reports:report-download", args=[report_id]))
    assert resp.status_code == 200
    assert resp["Content-Type"] == "application/pdf"
    content = b"".join(resp.streaming_content)
    assert content.startswith(b"%PDF")


def test_report_payload_includes_scan_context_and_file_size(analyst_client):
    scan = make_completed_scan_with_findings()
    resp = analyst_client.post(
        reverse("reports:report-list"),
        {"scan": str(scan.id), "report_type": "executive", "format": "json"},
        format="json",
    )
    assert resp.status_code == 201
    assert resp.data["scan_target"] == scan.target
    assert resp.data["scan_type"] == scan.scan_type
    assert resp.data["file_size"] > 0


def test_only_admin_can_delete_report(analyst_client, admin_client):
    scan = make_completed_scan_with_findings()
    create_resp = analyst_client.post(
        reverse("reports:report-list"),
        {"scan": str(scan.id), "report_type": "executive", "format": "json"},
        format="json",
    )
    report_id = create_resp.data["id"]
    url = reverse("reports:report-detail", args=[report_id])

    assert analyst_client.delete(url).status_code == 403
    assert admin_client.delete(url).status_code == 204
    assert not Report.objects.filter(id=report_id).exists()
