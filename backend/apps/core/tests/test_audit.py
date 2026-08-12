"""Testes da trilha de auditoria (RNF007, RN011)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.core.audit import record_audit
from apps.core.models import AuditLog

pytestmark = pytest.mark.django_db


def test_record_audit_persists_and_returns_entry():
    entry = record_audit("test.event", severity="info", source="1.2.3.4", foo="bar")
    assert AuditLog.objects.count() == 1
    assert entry.action == "test.event"
    assert entry.metadata["foo"] == "bar"


def test_rn011_audit_log_is_immutable():
    entry = record_audit("test.event")
    entry.action = "tampered"
    with pytest.raises(ValueError):
        entry.save()


def test_audit_endpoint_requires_admin(analyst_client):
    resp = analyst_client.get(reverse("core:audit-log-list"))
    assert resp.status_code == 403


def test_admin_can_list_audit_logs(admin_client):
    record_audit("scan.create", severity="info")
    resp = admin_client.get(reverse("core:audit-log-list"))
    assert resp.status_code == 200
    assert resp.data["count"] >= 1
