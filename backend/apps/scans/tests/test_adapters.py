"""Testes dos adapters de descoberta (com rede mockada — sem varredura real)."""

from __future__ import annotations

import pytest

import apps.scans.adapters as adapters_mod
from apps.assets.models import Asset, Service, Technology
from apps.scans.adapters import (
    CveLookupAdapter,
    DnsAdapter,
    HttpFingerprintAdapter,
    PortDiscoveryAdapter,
    ScanContext,
    TlsAdapter,
    get_adapters_for,
)

pytestmark = pytest.mark.django_db

CONTEXT = ScanContext(scan_id="x", authorized_by="CISO", authorization_scope="empresa.com")

NVD_ITEM = {
    "cve": {
        "id": "CVE-2024-9999",
        "descriptions": [{"lang": "en", "value": "Vulnerabilidade de exemplo."}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "baseSeverity": "HIGH",
                    "cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/..."},
                }
            ]
        },
        "references": [{"url": "https://example.com/cve"}],
    }
}


def test_port_discovery_reports_open_ports(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    adapter = PortDiscoveryAdapter(ports={22: "ssh", 80: "http", 3306: "mysql"})
    # Simula apenas 22 e 80 abertos.
    monkeypatch.setattr(PortDiscoveryAdapter, "_probe", lambda self, ip, port: port in {22, 80})

    results = adapter.run("empresa.com", CONTEXT)

    ports = sorted(r.data["port"] for r in results)
    assert ports == [22, 80]
    assert all(r.kind == "service" for r in results)
    assert all(r.data["ip"] == "192.168.0.10" for r in results)


def test_port_discovery_handles_unresolvable_host(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: None)
    assert PortDiscoveryAdapter().run("nope.invalid", CONTEXT) == []


def test_dns_adapter_parses_records(monkeypatch):
    class FakeRData:
        def __init__(self, text):
            self._text = text

        def to_text(self):
            return self._text

    def fake_resolve(target, rtype):
        if rtype == "A":
            return [FakeRData("192.168.0.10")]
        raise Exception("no record")

    import dns.resolver

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    results = DnsAdapter().run("empresa.com", CONTEXT)
    assert any(r.kind == "host" and r.data["ip"] == "192.168.0.10" for r in results)


def test_http_fingerprint_reports_technologies(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    adapter = HttpFingerprintAdapter(ports={80: "http"})
    # Simula a resposta HTTP sem tocar na rede.
    monkeypatch.setattr(
        HttpFingerprintAdapter,
        "_fetch",
        lambda self, url: ({"Server": "nginx/1.24.0"}, "<html>wp-content</html>"),
    )

    results = adapter.run("empresa.com", CONTEXT)

    assert all(r.kind == "technology" for r in results)
    names = {r.data["name"].lower() for r in results}
    assert "nginx" in names
    assert "wordpress" in names
    assert all(r.data["ip"] == "192.168.0.10" for r in results)


def test_http_fingerprint_skips_unreachable_ports(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    monkeypatch.setattr(HttpFingerprintAdapter, "_fetch", lambda self, url: None)
    assert HttpFingerprintAdapter(ports={80: "http"}).run("empresa.com", CONTEXT) == []


def test_tls_adapter_reports_negotiated_version(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    monkeypatch.setattr(
        TlsAdapter, "_probe_tls", lambda self, host: ("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256)
    )

    results = TlsAdapter().run("empresa.com", CONTEXT)

    assert len(results) == 1
    tech = results[0].data
    assert tech["category"] == "tls"
    assert tech["version"] == "TLSv1.3"


def test_tls_adapter_flags_deprecated_protocol(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: None)
    monkeypatch.setattr(TlsAdapter, "_probe_tls", lambda self, host: ("TLSv1", "AES128-SHA", 128))

    results = TlsAdapter().run("legacy.example", CONTEXT)
    assert "obsoleto" in results[0].data["evidence"]


def test_tls_adapter_handles_no_tls(monkeypatch):
    monkeypatch.setattr(TlsAdapter, "_probe_tls", lambda self, host: None)
    assert TlsAdapter().run("empresa.com", CONTEXT) == []


def test_registry_returns_adapters_per_scan_type():
    assert len(get_adapters_for("discovery")) == 2
    assert len(get_adapters_for("fingerprint")) == 2
    assert len(get_adapters_for("vulnerability")) == 1
    assert len(get_adapters_for("full")) == 5
    assert get_adapters_for("unknown") == []


def _asset_with_profile():
    asset = Asset.objects.create(ip="192.168.0.10", hostname="web01")
    Service.objects.create(
        asset=asset,
        port=443,
        protocol="tcp",
        service_name="https",
        product="nginx",
        version="1.18.0",
    )
    Technology.objects.create(
        asset=asset, category="framework", name="Django", version="3.2.0", source="http-cookie"
    )
    return asset


def test_cve_lookup_correlates_service_and_technology(monkeypatch):
    _asset_with_profile()
    monkeypatch.setattr(CveLookupAdapter, "_query_nvd", lambda self, keyword: [NVD_ITEM])
    adapter = CveLookupAdapter(request_delay=0)

    results = adapter.run("web01", CONTEXT)

    assert len(results) == 2  # um CVE por produto (nginx + Django)
    assert all(r.kind == "vulnerability" for r in results)
    assert all(r.data["cve"] == "CVE-2024-9999" for r in results)
    products = {r.data["product"] for r in results}
    assert products == {"nginx", "Django"}


def test_cve_lookup_returns_empty_without_matching_asset(monkeypatch):
    monkeypatch.setattr(CveLookupAdapter, "_query_nvd", lambda self, keyword: [NVD_ITEM])
    assert CveLookupAdapter(request_delay=0).run("nope.invalid", CONTEXT) == []


def test_cve_lookup_skips_services_without_product_or_version():
    asset = Asset.objects.create(ip="192.168.0.20", hostname="bare01")
    Service.objects.create(asset=asset, port=22, protocol="tcp", service_name="ssh")
    adapter = CveLookupAdapter(request_delay=0)
    assert adapter.run("bare01", CONTEXT) == []


def test_cve_lookup_ignores_nvd_errors(monkeypatch):
    _asset_with_profile()
    monkeypatch.setattr(CveLookupAdapter, "_query_nvd", lambda self, keyword: [])
    assert CveLookupAdapter(request_delay=0).run("web01", CONTEXT) == []


def test_cve_lookup_applies_request_delay_between_products(monkeypatch):
    _asset_with_profile()
    monkeypatch.setattr(CveLookupAdapter, "_query_nvd", lambda self, keyword: [])
    sleeps: list[float] = []
    monkeypatch.setattr(adapters_mod.time, "sleep", lambda s: sleeps.append(s))

    CveLookupAdapter(request_delay=6.0).run("web01", CONTEXT)

    assert sleeps == [6.0]  # 2 produtos → 1 pausa entre eles
