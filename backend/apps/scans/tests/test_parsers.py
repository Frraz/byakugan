"""Testes de normalização/persistência de resultados (inventário)."""

from __future__ import annotations

import pytest

from apps.assets.models import Asset, Service, Technology
from apps.scans.adapters import RawResult
from apps.scans.parsers import persist_results

pytestmark = pytest.mark.django_db


def test_persist_creates_assets_and_services():
    raw = [
        RawResult(
            kind="host", data={"hostname": "web01", "ip": "192.168.0.10", "domain": "empresa.com"}
        ),
        RawResult(
            kind="service",
            data={
                "ip": "192.168.0.10",
                "host": "web01",
                "port": 443,
                "protocol": "tcp",
                "service_name": "https",
            },
        ),
    ]
    summary = persist_results(raw)
    assert summary.assets == 1
    assert summary.services == 1
    assert Asset.objects.count() == 1
    assert Service.objects.filter(port=443).exists()


def test_persist_is_idempotent():
    raw = [
        RawResult(
            kind="service",
            data={"ip": "192.168.0.10", "port": 22, "protocol": "tcp", "service_name": "ssh"},
        ),
    ]
    persist_results(raw)
    persist_results(raw)
    assert Asset.objects.count() == 1
    assert Service.objects.filter(port=22).count() == 1


def _tech(category, name, **extra):
    return RawResult(
        kind="technology",
        data={
            "ip": "192.168.0.10",
            "hostname": "web01",
            "category": category,
            "name": name,
            "source": "http-header",
            "evidence": "Server: nginx/1.24.0",
            "confidence": "high",
            **extra,
        },
    )


def test_persist_creates_technologies():
    summary = persist_results([_tech("web-server", "nginx", version="1.24.0")])
    assert summary.technologies == 1
    tech = Technology.objects.get()
    assert tech.name == "nginx"
    assert tech.version == "1.24.0"
    assert tech.asset.ip == "192.168.0.10"


def test_technology_persist_is_idempotent():
    raw = [_tech("framework", "Django")]
    persist_results(raw)
    persist_results(raw)
    assert Technology.objects.filter(name="Django").count() == 1


def test_os_technology_enriches_asset_os():
    persist_results([_tech("os", "Ubuntu", version=None)])
    assert Asset.objects.get().os == "Ubuntu"


def test_web_server_technology_enriches_matching_service():
    persist_results(
        [
            RawResult(
                kind="service",
                data={
                    "ip": "192.168.0.10",
                    "hostname": "web01",
                    "port": 443,
                    "protocol": "tcp",
                    "service_name": "https",
                },
            ),
            _tech("web-server", "nginx", version="1.24.0", port=443),
        ]
    )
    service = Service.objects.get(port=443)
    assert service.product == "nginx"
    assert service.version == "1.24.0"
