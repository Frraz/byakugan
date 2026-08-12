"""Testes da orquestração de scan (run_scan)."""

from __future__ import annotations

import pytest

import apps.scans.tasks as tasks_mod
from apps.assets.models import Asset
from apps.core.models import AuditLog
from apps.scans.adapters import RawResult, ScannerAdapter
from apps.scans.models import Scan
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


class _FakeAdapter(ScannerAdapter):
    name = "fake"
    scan_type = "discovery"

    def run(self, target, context):
        return [
            RawResult(
                kind="service",
                data={"ip": "192.168.0.10", "port": 80, "protocol": "tcp", "service_name": "http"},
            ),
        ]


def test_killswitch_blocks_scan(settings):
    settings.BYAKUGAN_SCANNING_ENABLED = False
    scan = ScanFactory()
    result = tasks_mod.run_scan(str(scan.id))
    scan.refresh_from_db()
    assert scan.status == Scan.Status.FAILED
    assert result["reason"] == "scanning_disabled"
    assert AuditLog.objects.filter(action="scan.blocked").exists()


def test_run_scan_completes_and_persists(settings, monkeypatch):
    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(tasks_mod, "get_adapters_for", lambda scan_type: [_FakeAdapter()])
    scan = ScanFactory()

    result = tasks_mod.run_scan(str(scan.id))

    scan.refresh_from_db()
    assert scan.status == Scan.Status.COMPLETED
    assert result["services"] == 1
    assert Asset.objects.filter(ip="192.168.0.10").exists()
    assert AuditLog.objects.filter(action="scan.completed").exists()
