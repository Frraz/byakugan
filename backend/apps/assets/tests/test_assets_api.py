"""Testes de integração da API de inventário (RF007)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.assets.models import Asset, DnsRecord, Service, Technology

pytestmark = pytest.mark.django_db


@pytest.fixture
def asset_with_service(db):
    asset = Asset.objects.create(ip="192.168.0.10", hostname="web01")
    Service.objects.create(asset=asset, port=443, protocol="tcp", service_name="https")
    Technology.objects.create(
        asset=asset,
        category="web-server",
        name="nginx",
        version="1.24.0",
        source="http-header",
        confidence="high",
    )
    return asset


@pytest.fixture
def asset_with_dns_record(db):
    asset = Asset.objects.create(domain="empresa.com")
    DnsRecord.objects.create(
        asset=asset,
        domain="empresa.com",
        record_type="TXT",
        value="v=spf1 include:_spf.google.com ~all",
    )
    return asset


def test_list_assets_requires_auth(api_client):
    assert api_client.get(reverse("assets:asset-list")).status_code == 401


def test_viewer_can_list_assets(viewer_client, asset_with_service):
    resp = viewer_client.get(reverse("assets:asset-list"))
    assert resp.status_code == 200
    assert resp.data["count"] == 1


def test_asset_detail_includes_services(viewer_client, asset_with_service):
    resp = viewer_client.get(reverse("assets:asset-detail", args=[asset_with_service.id]))
    assert resp.status_code == 200
    assert len(resp.data["services"]) == 1
    assert resp.data["services"][0]["port"] == 443


def test_asset_services_endpoint(viewer_client, asset_with_service):
    resp = viewer_client.get(reverse("assets:asset-services", args=[asset_with_service.id]))
    assert resp.status_code == 200
    assert resp.data[0]["service_name"] == "https"


def test_asset_detail_includes_technologies(viewer_client, asset_with_service):
    resp = viewer_client.get(reverse("assets:asset-detail", args=[asset_with_service.id]))
    assert resp.status_code == 200
    assert len(resp.data["technologies"]) == 1
    assert resp.data["technologies"][0]["name"] == "nginx"


def test_asset_technologies_endpoint(viewer_client, asset_with_service):
    resp = viewer_client.get(reverse("assets:asset-technologies", args=[asset_with_service.id]))
    assert resp.status_code == 200
    assert resp.data[0]["category"] == "web-server"
    assert resp.data[0]["version"] == "1.24.0"


def test_asset_detail_includes_dns_records(viewer_client, asset_with_dns_record):
    resp = viewer_client.get(reverse("assets:asset-detail", args=[asset_with_dns_record.id]))
    assert resp.status_code == 200
    assert len(resp.data["dns_records"]) == 1
    assert resp.data["dns_records"][0]["record_type"] == "TXT"


def test_asset_dns_records_endpoint(viewer_client, asset_with_dns_record):
    resp = viewer_client.get(reverse("assets:asset-dns-records", args=[asset_with_dns_record.id]))
    assert resp.status_code == 200
    assert resp.data[0]["record_type"] == "TXT"
    assert "spf1" in resp.data[0]["value"]


def test_asset_without_dns_records_returns_empty_list(viewer_client, asset_with_service):
    resp = viewer_client.get(reverse("assets:asset-dns-records", args=[asset_with_service.id]))
    assert resp.status_code == 200
    assert resp.data == []
