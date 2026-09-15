"""Testes do endpoint de vulnerabilidades consolidadas (GET /api/findings/grouped/).

A mesma vulnerabilidade encontrada em vários alvos deve aparecer numa única
linha (o dedup_key por-ativo não deduplica entre alvos), com a contagem de
alvos afetados e as ocorrências para o painel de detalhe.
"""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.assets.models import Asset
from apps.scans.models import Finding
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


def _finding(asset, scan, *, title, category="injection", severity="high", cvss=7.5):
    return Finding.objects.create(
        scan=scan,
        asset=asset,
        category=category,
        title=title,
        severity=severity,
        cvss=cvss,
        description="d",
        evidence="e",
        recommendation="r",
        dedup_key=f"{asset.id}:{category}:{title}",
    )


def test_grouped_requires_auth(api_client):
    assert api_client.get(reverse("scans:finding-grouped")).status_code == 401


def test_same_vuln_across_targets_is_one_group(viewer_client):
    scan = ScanFactory()
    asset_a = Asset.objects.create(ip="192.168.0.10", hostname="a")
    asset_b = Asset.objects.create(ip="192.168.0.20", hostname="b")
    _finding(asset_a, scan, title="SQL Injection")
    _finding(asset_b, scan, title="SQL Injection")

    resp = viewer_client.get(reverse("scans:finding-grouped"))
    assert resp.status_code == 200
    assert len(resp.data["results"]) == 1
    group = resp.data["results"][0]
    assert group["title"] == "SQL Injection"
    assert group["targets"] == 2
    assert group["occurrences"] == 2
    assert len(group["affected"]) == 2


def test_distinct_titles_are_distinct_groups(viewer_client):
    scan = ScanFactory()
    asset = Asset.objects.create(ip="192.168.0.10")
    _finding(asset, scan, title="SQL Injection", severity="high")
    _finding(asset, scan, title="Reflected XSS", category="injection", severity="medium")

    resp = viewer_client.get(reverse("scans:finding-grouped"))
    assert resp.status_code == 200
    assert len(resp.data["results"]) == 2
    # Ordenado por severidade máxima: high antes de medium.
    assert resp.data["results"][0]["title"] == "SQL Injection"


def test_grouped_max_severity_wins(viewer_client):
    scan = ScanFactory()
    asset_a = Asset.objects.create(ip="192.168.0.10", hostname="a")
    asset_b = Asset.objects.create(ip="192.168.0.20", hostname="b")
    _finding(asset_a, scan, title="SQL Injection", severity="low", cvss=3.0)
    _finding(asset_b, scan, title="SQL Injection", severity="critical", cvss=9.8)

    resp = viewer_client.get(reverse("scans:finding-grouped"))
    group = resp.data["results"][0]
    assert group["severity"] == "critical"
    assert group["cvss"] == 9.8
