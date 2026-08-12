"""Testes da orquestração de scan (run_scan)."""

from __future__ import annotations

import pytest

import apps.scans.tasks as tasks_mod
from apps.assets.models import Asset
from apps.core.models import AuditLog
from apps.scans.adapters import RawResult, ScannerAdapter
from apps.scans.models import Finding, Scan
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


class _FakeDiscoveryAdapter(ScannerAdapter):
    name = "fake-discovery"
    scan_type = "discovery"

    def run(self, target, context):
        return [
            RawResult(
                kind="service",
                data={"ip": "192.168.0.20", "port": 80, "protocol": "tcp", "service_name": "http"},
            )
        ]


class _FakeVulnerabilityAdapter(ScannerAdapter):
    """Só produz resultado se o asset da fase de discovery já estiver persistido."""

    name = "fake-vuln"
    scan_type = "vulnerability"

    def run(self, target, context):
        asset = Asset.objects.filter(ip="192.168.0.20").first()
        if asset is None:
            return []
        return [
            RawResult(
                kind="vulnerability",
                data={
                    "asset_id": str(asset.id),
                    "cve": "CVE-2024-0001",
                    "title": "CVE-2024-0001 em http",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "cvss_vector": None,
                    "description": "Descrição.",
                    "references": [],
                    "category": "software",
                    "evidence": "evidência",
                    "recommendation": "recomendação",
                    "product": "http",
                    "product_version": "1.0",
                },
            )
        ]


def test_run_scan_persists_profile_before_vulnerability_phase(settings, monkeypatch):
    """RN da Fase 3: o CveLookupAdapter só vê o profile já persistido nesta execução."""
    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(
        tasks_mod,
        "get_adapters_for",
        lambda scan_type: [_FakeDiscoveryAdapter(), _FakeVulnerabilityAdapter()],
    )
    scan = ScanFactory(scan_type=Scan.ScanType.FULL)

    result = tasks_mod.run_scan(str(scan.id))

    scan.refresh_from_db()
    assert scan.status == Scan.Status.COMPLETED
    assert result["findings"] == 1
    assert Finding.objects.filter(scan=scan).exists()
