"""Testes de integração da API de Targets e Scans (RBAC, RN002, RN007)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.scans.models import Scan
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
