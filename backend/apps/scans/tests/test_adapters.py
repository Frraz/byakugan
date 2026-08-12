"""Testes dos adapters de descoberta (com rede mockada — sem varredura real)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone as django_timezone

import apps.scans.adapters as adapters_mod
from apps.assets.models import Asset, Service, Technology
from apps.scans.adapters import (
    CveLookupAdapter,
    DefaultCredsAdapter,
    DnsAdapter,
    EmailSecurityAdapter,
    HttpFingerprintAdapter,
    PortDiscoveryAdapter,
    ScanContext,
    SubdomainAdapter,
    TlsAdapter,
    UdpProbeAdapter,
    WebScanAdapter,
    ZoneTransferAdapter,
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
    # Simula apenas 22 e 80 abertos, sem banner.
    monkeypatch.setattr(
        PortDiscoveryAdapter, "_probe", lambda self, ip, port: (port in {22, 80}, b"")
    )

    results = adapter.run("empresa.com", CONTEXT)

    ports = sorted(r.data["port"] for r in results)
    assert ports == [22, 80]
    assert all(r.kind == "service" for r in results)
    assert all(r.data["ip"] == "192.168.0.10" for r in results)


def test_port_discovery_handles_unresolvable_host(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: None)
    assert PortDiscoveryAdapter().run("nope.invalid", CONTEXT) == []


def test_port_discovery_extracts_product_version_from_banner(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    adapter = PortDiscoveryAdapter(ports={22: "ssh"})
    monkeypatch.setattr(
        PortDiscoveryAdapter,
        "_probe",
        lambda self, ip, port: (True, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"),
    )

    results = adapter.run("empresa.com", CONTEXT)

    assert len(results) == 1
    data = results[0].data
    assert data["product"] == "OpenSSH"
    assert data["version"] == "8.2p1"
    assert data["service_name"] == "ssh"


def test_port_discovery_keeps_default_service_name_without_banner_match(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    adapter = PortDiscoveryAdapter(ports={9999: "unknown"})
    monkeypatch.setattr(PortDiscoveryAdapter, "_probe", lambda self, ip, port: (True, b"garbage"))

    results = adapter.run("empresa.com", CONTEXT)

    assert results[0].data["service_name"] == "unknown"
    assert "product" not in results[0].data


def test_port_discovery_uses_port_set_from_options(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    probed_ports: list[int] = []
    monkeypatch.setattr(
        PortDiscoveryAdapter,
        "_probe",
        lambda self, ip, port: (probed_ports.append(port) or False, b""),
    )
    adapter = PortDiscoveryAdapter()  # sem ports fixo — resolve via options
    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="empresa.com",
        options={"port_set": "top16"},
    )

    adapter.run("empresa.com", context)

    assert set(probed_ports) == set(adapters_mod.DEFAULT_PORTS)


def test_port_discovery_defaults_to_top100_without_explicit_port_set(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    probed_ports: list[int] = []
    monkeypatch.setattr(
        PortDiscoveryAdapter,
        "_probe",
        lambda self, ip, port: (probed_ports.append(port) or False, b""),
    )
    adapter = PortDiscoveryAdapter()

    adapter.run("empresa.com", CONTEXT)  # CONTEXT.options == {}

    from apps.scans.data.ports import TOP_100

    assert set(probed_ports) == set(TOP_100)


# --- UdpProbeAdapter --------------------------------------------------------


def test_udp_probe_reports_responding_ports(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    adapter = UdpProbeAdapter(probes={53: b"query", 123: b"ntp"})
    monkeypatch.setattr(UdpProbeAdapter, "_probe_udp", lambda self, ip, port, payload: port == 53)

    results = adapter.run("empresa.com", CONTEXT)

    assert len(results) == 1
    assert results[0].data["port"] == 53
    assert results[0].data["protocol"] == "udp"
    assert results[0].data["service_name"] == "dns"


def test_udp_probe_handles_unresolvable_host(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: None)
    assert UdpProbeAdapter().run("nope.invalid", CONTEXT) == []


def test_udp_probe_returns_empty_when_nothing_responds(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    adapter = UdpProbeAdapter(probes={53: b"query"})
    monkeypatch.setattr(UdpProbeAdapter, "_probe_udp", lambda self, ip, port, payload: False)
    assert adapter.run("empresa.com", CONTEXT) == []


# --- DefaultCredsAdapter -----------------------------------------------------


def _asset_with_open_ports(*ports_and_names: tuple[int, str]) -> Asset:
    asset = Asset.objects.create(ip="192.168.0.30", hostname="creds01")
    for port, name in ports_and_names:
        Service.objects.create(asset=asset, port=port, protocol="tcp", service_name=name)
    return asset


AGGRESSIVE_CONTEXT = ScanContext(
    scan_id="x",
    authorized_by="CISO",
    authorization_scope="creds01",
    options={"intensity": "aggressive"},
)


def test_default_creds_gated_by_intensity(monkeypatch):
    """Sem intensidade aggressive, o adapter nunca tenta credenciais."""
    _asset_with_open_ports((21, "ftp"))
    called = []
    monkeypatch.setattr(
        DefaultCredsAdapter, "_try_login", lambda self, kind, host, port: called.append(kind)
    )

    results = DefaultCredsAdapter().run("creds01", CONTEXT)  # CONTEXT sem intensity aggressive

    assert results == []
    assert called == []


def test_default_creds_skips_when_out_of_scope():
    _asset_with_open_ports((21, "ftp"))
    out_of_scope_context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="outro-dominio.com",
        options={"intensity": "aggressive"},
    )
    assert DefaultCredsAdapter().run("creds01", out_of_scope_context) == []


def test_default_creds_reports_ftp_anonymous_success(monkeypatch):
    asset = _asset_with_open_ports((21, "ftp"))
    monkeypatch.setattr(
        DefaultCredsAdapter,
        "_try_login",
        lambda self, kind, host, port: (
            (True, "Login FTP anônimo aceito.") if kind == "ftp-anonymous" else None
        ),
    )

    results = DefaultCredsAdapter().run("creds01", AGGRESSIVE_CONTEXT)

    assert len(results) == 1
    assert results[0].kind == "vulnerability"
    assert results[0].data["category"] == "credential"
    assert results[0].data["asset_id"] == str(asset.id)
    assert results[0].data["evidence"] == "Login FTP anônimo aceito."
    assert results[0].data["description"]
    assert results[0].data["recommendation"]


def test_default_creds_no_finding_when_login_fails(monkeypatch):
    _asset_with_open_ports((21, "ftp"))
    monkeypatch.setattr(
        DefaultCredsAdapter, "_try_login", lambda self, kind, host, port: (False, "")
    )
    assert DefaultCredsAdapter().run("creds01", AGGRESSIVE_CONTEXT) == []


def test_default_creds_only_tests_open_ports(monkeypatch):
    """Portas não descobertas como abertas não são tentadas."""
    _asset_with_open_ports((22, "ssh"))  # nem ftp, redis, es ou http admin
    called = []
    monkeypatch.setattr(
        DefaultCredsAdapter,
        "_try_login",
        lambda self, kind, host, port: called.append((kind, port)),
    )

    DefaultCredsAdapter().run("creds01", AGGRESSIVE_CONTEXT)

    assert called == []


def test_default_creds_tests_http_basic_and_actuator_on_admin_ports(monkeypatch):
    _asset_with_open_ports((8080, "http-alt"))
    seen_kinds = []
    monkeypatch.setattr(
        DefaultCredsAdapter,
        "_try_login",
        lambda self, kind, host, port: (seen_kinds.append(kind), None)[1],
    )

    DefaultCredsAdapter().run("creds01", AGGRESSIVE_CONTEXT)

    assert set(seen_kinds) == {"http-basic-default", "actuator-exposed"}


def test_default_creds_returns_none_for_unmapped_asset():
    assert DefaultCredsAdapter().run("nope.invalid", AGGRESSIVE_CONTEXT) == []


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


def _mock_tls_network(monkeypatch, *, versions=None, cert=None):
    """Evita qualquer chamada de rede real dos seams novos da Fase 2."""
    monkeypatch.setattr(TlsAdapter, "_probe_versions", lambda self, host: versions or [])
    monkeypatch.setattr(TlsAdapter, "_get_cert", lambda self, host: cert)


def test_tls_adapter_reports_negotiated_version(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    monkeypatch.setattr(
        TlsAdapter, "_probe_tls", lambda self, host: ("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256)
    )
    _mock_tls_network(monkeypatch, versions=["TLSv1.3"])

    results = TlsAdapter().run("empresa.com", CONTEXT)

    technologies = [r for r in results if r.kind == "technology"]
    assert len(technologies) == 1
    tech = technologies[0].data
    assert tech["category"] == "tls"
    assert tech["version"] == "TLSv1.3"
    # Protocolo moderno + cipher forte + sem certificado coletado → sem findings.
    assert not any(r.kind == "vulnerability" for r in results)


def test_tls_adapter_flags_deprecated_protocol(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: None)
    monkeypatch.setattr(TlsAdapter, "_probe_tls", lambda self, host: ("TLSv1", "AES128-SHA", 128))
    _mock_tls_network(monkeypatch, versions=["TLSv1"])

    results = TlsAdapter().run("legacy.example", CONTEXT)

    technology = next(r for r in results if r.kind == "technology")
    assert "obsoleto" in technology.data["evidence"]
    vulnerabilities = [r for r in results if r.kind == "vulnerability"]
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].data["category"] == "tls"
    assert vulnerabilities[0].data["title"] == "Protocolo TLS obsoleto habilitado"


def test_tls_adapter_handles_no_tls(monkeypatch):
    monkeypatch.setattr(TlsAdapter, "_probe_tls", lambda self, host: None)
    assert TlsAdapter().run("empresa.com", CONTEXT) == []


def test_tls_adapter_emits_certificate_findings(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    monkeypatch.setattr(
        TlsAdapter, "_probe_tls", lambda self, host: ("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256)
    )
    now = django_timezone.now()
    expired_cert = {
        "not_valid_before": now - timedelta(days=400),
        "not_valid_after": now - timedelta(days=5),
        "issuer": "CN=self",
        "subject": "CN=self",
        "san": [],
        "key_type": "RSA",
        "key_size": 1024,
        "signature_algorithm": "sha1",
    }
    _mock_tls_network(monkeypatch, versions=["TLSv1.3"], cert=expired_cert)

    results = TlsAdapter().run("empresa.com", CONTEXT)

    findings = [r for r in results if r.kind == "vulnerability"]
    titles = {f.data["title"] for f in findings}
    assert "Certificado TLS expirado" in titles
    assert "Certificado TLS autoassinado" in titles
    assert "Certificado TLS sem Subject Alternative Name (SAN)" in titles
    for f in findings:
        assert f.data["host"] == "empresa.com"
        assert f.data["ip"] == "192.168.0.10"
        assert "asset_id" not in f.data  # resolvido por ip/hostname no parser, não aqui


def test_tls_adapter_no_findings_when_cert_healthy_and_protocol_modern(monkeypatch):
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.168.0.10")
    monkeypatch.setattr(
        TlsAdapter, "_probe_tls", lambda self, host: ("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256)
    )
    now = django_timezone.now()
    healthy_cert = {
        "not_valid_before": now - timedelta(days=1),
        "not_valid_after": now + timedelta(days=300),
        "issuer": "CN=Trusted CA",
        "subject": "CN=empresa.com",
        "san": ["empresa.com"],
        "key_type": "RSA",
        "key_size": 2048,
        "signature_algorithm": "sha256",
    }
    _mock_tls_network(monkeypatch, versions=["TLSv1.2", "TLSv1.3"], cert=healthy_cert)

    results = TlsAdapter().run("empresa.com", CONTEXT)

    assert not any(r.kind == "vulnerability" for r in results)


def test_registry_returns_adapters_per_scan_type():
    # Asserts por nome (não contagem) — futuras fases adicionam adapters sem
    # quebrar este teste; o que importa é que os adapters atuais continuam
    # registrados no scan_type certo.
    assert {a.name for a in get_adapters_for("discovery")} >= {
        "dns",
        "port-discovery",
        "udp-probe",
        "subdomain-enum",
        "zone-transfer",
        "email-security",
    }
    assert {a.name for a in get_adapters_for("fingerprint")} >= {"http-fingerprint", "tls"}
    assert {a.name for a in get_adapters_for("vulnerability")} >= {
        "cve-lookup",
        "default-creds",
        "web-scan",
    }
    assert {a.name for a in get_adapters_for("full")} >= {
        "dns",
        "port-discovery",
        "udp-probe",
        "subdomain-enum",
        "zone-transfer",
        "email-security",
        "http-fingerprint",
        "tls",
        "cve-lookup",
        "default-creds",
        "web-scan",
    }
    assert get_adapters_for("unknown") == []


def test_registry_filters_by_enabled_checks_option():
    adapters = get_adapters_for("full", {"enabled_checks": ["dns", "tls"]})
    assert {a.name for a in adapters} == {"dns", "tls"}


def test_registry_returns_all_when_enabled_checks_is_none():
    all_adapters = get_adapters_for("full", {"enabled_checks": None})
    assert len(all_adapters) == len(get_adapters_for("full"))


def test_registry_enabled_checks_empty_list_excludes_all():
    assert get_adapters_for("full", {"enabled_checks": []}) == []


def test_context_check_cancelled_noop_without_should_abort():
    CONTEXT.check_cancelled()  # não deve levantar


def test_context_check_cancelled_raises_when_should_abort_true():
    from apps.scans.adapters import ScanCancelled

    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="empresa.com",
        should_abort=lambda: True,
    )
    with pytest.raises(ScanCancelled):
        context.check_cancelled()


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
    monkeypatch.setattr(
        CveLookupAdapter, "_query_nvd", lambda self, *, cpe_match=None, keyword=None: [NVD_ITEM]
    )
    adapter = CveLookupAdapter(request_delay=0)

    results = adapter.run("web01", CONTEXT)

    assert len(results) == 2  # um CVE por produto (nginx + Django)
    assert all(r.kind == "vulnerability" for r in results)
    assert all(r.data["cve"] == "CVE-2024-9999" for r in results)
    products = {r.data["product"] for r in results}
    assert products == {"nginx", "Django"}


def test_cve_lookup_returns_empty_without_matching_asset(monkeypatch):
    monkeypatch.setattr(
        CveLookupAdapter, "_query_nvd", lambda self, *, cpe_match=None, keyword=None: [NVD_ITEM]
    )
    assert CveLookupAdapter(request_delay=0).run("nope.invalid", CONTEXT) == []


def test_cve_lookup_skips_services_without_product_or_version():
    asset = Asset.objects.create(ip="192.168.0.20", hostname="bare01")
    Service.objects.create(asset=asset, port=22, protocol="tcp", service_name="ssh")
    adapter = CveLookupAdapter(request_delay=0)
    assert adapter.run("bare01", CONTEXT) == []


def test_cve_lookup_queries_by_cpe_first(monkeypatch):
    """CPE é tentado antes de keyword — evidência registra qual busca deu match."""
    _asset_with_profile()
    calls = []

    def fake_query_nvd(self, *, cpe_match=None, keyword=None):
        calls.append({"cpe_match": cpe_match, "keyword": keyword})
        return [NVD_ITEM] if cpe_match else []

    monkeypatch.setattr(CveLookupAdapter, "_query_nvd", fake_query_nvd)

    results = CveLookupAdapter(request_delay=0).run("web01", CONTEXT)

    assert len(results) == 2
    assert all("virtualMatchString" in r.data["evidence"] for r in results)
    # nginx e Django, cada um com CPE tentado — keyword nunca precisou ser usado.
    assert all(c["cpe_match"] is not None for c in calls)
    assert not any(c["keyword"] is not None for c in calls)


def test_cve_lookup_falls_back_to_keyword_when_cpe_finds_nothing(monkeypatch):
    _asset_with_profile()
    calls = []

    def fake_query_nvd(self, *, cpe_match=None, keyword=None):
        calls.append({"cpe_match": cpe_match, "keyword": keyword})
        return [] if cpe_match else [NVD_ITEM]

    monkeypatch.setattr(CveLookupAdapter, "_query_nvd", fake_query_nvd)

    results = CveLookupAdapter(request_delay=0).run("web01", CONTEXT)

    assert len(results) == 2
    assert all("keywordSearch" in r.data["evidence"] for r in results)
    # Cada produto: 1 tentativa por CPE (sem sucesso) + 1 por keyword (com sucesso).
    assert len([c for c in calls if c["cpe_match"] is not None]) == 2
    assert len([c for c in calls if c["keyword"] is not None]) == 2


def test_cve_lookup_cpe_match_uses_correct_product_and_version(monkeypatch):
    asset = Asset.objects.create(ip="192.168.0.10", hostname="web02")
    Service.objects.create(
        asset=asset,
        port=443,
        protocol="tcp",
        service_name="https",
        product="nginx",
        version="1.24.0",
    )
    captured_cpe = []

    def _fake_query(self, *, cpe_match=None, keyword=None):
        captured_cpe.append(cpe_match)
        return [] if cpe_match is None else [NVD_ITEM]  # não-vazio: não aciona fallback

    monkeypatch.setattr(CveLookupAdapter, "_query_nvd", _fake_query)

    CveLookupAdapter(request_delay=0).run("web02", CONTEXT)

    assert captured_cpe == ["cpe:2.3:a:*:nginx:1.24.0:*"]


def test_cve_lookup_ignores_nvd_errors(monkeypatch):
    _asset_with_profile()
    monkeypatch.setattr(
        CveLookupAdapter, "_query_nvd", lambda self, *, cpe_match=None, keyword=None: []
    )
    assert CveLookupAdapter(request_delay=0).run("web01", CONTEXT) == []


def test_cve_lookup_applies_request_delay_between_products(monkeypatch):
    _asset_with_profile()
    monkeypatch.setattr(
        CveLookupAdapter, "_query_nvd", lambda self, *, cpe_match=None, keyword=None: []
    )
    sleeps: list[float] = []
    monkeypatch.setattr(adapters_mod.time, "sleep", lambda s: sleeps.append(s))

    CveLookupAdapter(request_delay=6.0).run("web01", CONTEXT)

    assert sleeps == [6.0]  # 2 produtos → 1 pausa entre eles


# --- SubdomainAdapter --------------------------------------------------------

DOMAIN_CONTEXT = ScanContext(scan_id="x", authorized_by="CISO", authorization_scope="empresa.com")


def test_subdomain_adapter_resolves_wordlist_candidates(monkeypatch):
    monkeypatch.setattr(SubdomainAdapter, "_fetch_crtsh", lambda self, domain: [])

    def fake_resolve(self, hostname):
        return {"www.empresa.com": "192.168.0.10", "mail.empresa.com": "192.168.0.11"}.get(hostname)

    monkeypatch.setattr(SubdomainAdapter, "_resolve", fake_resolve)

    results = SubdomainAdapter().run("empresa.com", DOMAIN_CONTEXT)

    hostnames = {r.data["hostname"] for r in results}
    assert hostnames == {"www.empresa.com", "mail.empresa.com"}
    assert all(r.kind == "host" for r in results)
    assert all(r.data["domain"] == "empresa.com" for r in results)


def test_subdomain_adapter_includes_crtsh_candidates(monkeypatch):
    monkeypatch.setattr(SubdomainAdapter, "_resolve", lambda self, hostname: "10.0.0.5")
    monkeypatch.setattr(
        SubdomainAdapter,
        "_fetch_crtsh",
        lambda self, domain: [
            {"name_value": "grafana.empresa.com\n*.internal.empresa.com"},
            {"name_value": "empresa.com"},  # o próprio domínio — não deve virar candidato
            {"name_value": "totally-unrelated.other.com"},  # domínio diferente — ignorado
        ],
    )
    # Zera a wordlist pra isolar o que vem só do crt.sh.
    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="empresa.com",
        options={"wordlist_size": 0},
    )

    results = SubdomainAdapter().run("empresa.com", context)

    hostnames = {r.data["hostname"] for r in results}
    assert "grafana.empresa.com" in hostnames
    assert "internal.empresa.com" in hostnames  # wildcard "*." removido
    assert "empresa.com" not in hostnames
    assert "totally-unrelated.other.com" not in hostnames


def test_subdomain_adapter_skips_non_domain_targets(monkeypatch):
    called = []
    monkeypatch.setattr(SubdomainAdapter, "_resolve", lambda self, h: called.append(h))
    monkeypatch.setattr(SubdomainAdapter, "_fetch_crtsh", lambda self, d: [])

    assert SubdomainAdapter().run("192.168.0.10", DOMAIN_CONTEXT) == []
    assert SubdomainAdapter().run("10.0.0.0/24", DOMAIN_CONTEXT) == []
    assert called == []


def test_subdomain_adapter_excludes_out_of_scope_candidates(monkeypatch):
    monkeypatch.setattr(SubdomainAdapter, "_fetch_crtsh", lambda self, domain: [])
    resolved = []

    def fake_resolve(self, hostname):
        resolved.append(hostname)
        return "192.168.0.10"

    monkeypatch.setattr(SubdomainAdapter, "_resolve", fake_resolve)
    out_of_scope_context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="outro-dominio.com",
        options={"wordlist_size": 5},
    )

    results = SubdomainAdapter().run("empresa.com", out_of_scope_context)

    assert results == []
    assert resolved == []  # nem tentou resolver — filtrado antes por escopo


def test_subdomain_adapter_respects_wordlist_size(monkeypatch):
    monkeypatch.setattr(SubdomainAdapter, "_fetch_crtsh", lambda self, domain: [])
    attempted = []

    def fake_resolve(self, hostname):
        attempted.append(hostname)
        return None

    monkeypatch.setattr(SubdomainAdapter, "_resolve", fake_resolve)
    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="empresa.com",
        options={"wordlist_size": 5},
    )

    SubdomainAdapter().run("empresa.com", context)

    assert len(attempted) == 5


def test_subdomain_adapter_unresolved_candidates_produce_no_results(monkeypatch):
    monkeypatch.setattr(SubdomainAdapter, "_fetch_crtsh", lambda self, domain: [])
    monkeypatch.setattr(SubdomainAdapter, "_resolve", lambda self, hostname: None)
    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="empresa.com",
        options={"wordlist_size": 3},
    )

    assert SubdomainAdapter().run("empresa.com", context) == []


# --- ZoneTransferAdapter -----------------------------------------------------


def test_zone_transfer_no_findings_when_all_nameservers_refuse(monkeypatch):
    monkeypatch.setattr(ZoneTransferAdapter, "_nameservers", lambda self, d: ["ns1.empresa.com"])
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.0.2.1")
    monkeypatch.setattr(ZoneTransferAdapter, "_axfr", lambda self, ip, domain: [])

    assert ZoneTransferAdapter().run("empresa.com", DOMAIN_CONTEXT) == []


def test_zone_transfer_reports_vulnerability_and_leaked_records(monkeypatch):
    monkeypatch.setattr(ZoneTransferAdapter, "_nameservers", lambda self, d: ["ns1.empresa.com"])
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: "192.0.2.1")
    monkeypatch.setattr(
        ZoneTransferAdapter,
        "_axfr",
        lambda self, ip, domain: [
            ("empresa.com", "SOA", "ns1.empresa.com. admin.empresa.com. 1 3600 900 604800 3600"),
            ("empresa.com", "NS", "ns1.empresa.com."),
            ("www.empresa.com", "A", "192.168.1.10"),
            ("internal-db.empresa.com", "A", "10.0.0.5"),
        ],
    )

    results = ZoneTransferAdapter().run("empresa.com", DOMAIN_CONTEXT)

    vulnerabilities = [r for r in results if r.kind == "vulnerability"]
    hosts = [r for r in results if r.kind == "host"]
    dns_records = [r for r in results if r.kind == "dns_record"]

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].data["category"] == "dns"
    assert vulnerabilities[0].data["severity"] == "high"
    assert "ns1.empresa.com" in vulnerabilities[0].data["title"]

    assert {h.data["hostname"] for h in hosts} == {"www.empresa.com", "internal-db.empresa.com"}
    assert {h.data["ip"] for h in hosts} == {"192.168.1.10", "10.0.0.5"}

    assert {(d.data["record_type"]) for d in dns_records} == {"SOA", "NS"}


def test_zone_transfer_skips_non_domain_targets(monkeypatch):
    called = []
    monkeypatch.setattr(ZoneTransferAdapter, "_nameservers", lambda self, d: called.append(d))
    assert ZoneTransferAdapter().run("192.168.0.10", DOMAIN_CONTEXT) == []
    assert called == []


def test_zone_transfer_skips_nameservers_that_do_not_resolve(monkeypatch):
    monkeypatch.setattr(ZoneTransferAdapter, "_nameservers", lambda self, d: ["ns1.empresa.com"])
    monkeypatch.setattr(adapters_mod, "_resolve_ip", lambda host: None)
    called = []
    monkeypatch.setattr(
        ZoneTransferAdapter, "_axfr", lambda self, ip, domain: called.append(ip) or []
    )

    assert ZoneTransferAdapter().run("empresa.com", DOMAIN_CONTEXT) == []
    assert called == []  # _axfr nunca chamado sem IP resolvido


def test_axfr_extracts_records_from_a_real_zone(monkeypatch):
    """Verifica a lógica REAL de extração de _axfr (não o seam) contra uma
    zona dnspython genuína — só troca dns.query.xfr/dns.zone.from_xfr pela
    construção via dns.zone.from_text, sem tocar rede."""
    import dns.zone

    # Sem indentação: o parser de zonefile do dnspython é sensível a espaço em
    # branco à esquerda (significa "mesmo owner name da linha anterior").
    zone_text = (
        "@ 3600 IN SOA ns1.empresa.com. admin.empresa.com. 1 3600 900 604800 3600\n"
        "@ 3600 IN NS ns1.empresa.com.\n"
        "www 3600 IN A 192.168.1.10\n"
        "internal-db 3600 IN A 10.0.0.5\n"
    )
    zone = dns.zone.from_text(zone_text, origin="empresa.com", relativize=False)

    import dns.query

    # dns.zone/dns.query são importados dentro do método (import tardio) —
    # monkeypatch nos módulos reais afeta esse import tardio também, já que
    # `import` só religa o nome ao módulo já em sys.modules (mesmo padrão de
    # test_dns_adapter_parses_records, que faz o mesmo com dns.resolver).
    monkeypatch.setattr(dns.zone, "from_xfr", lambda xfr, relativize: zone)
    monkeypatch.setattr(dns.query, "xfr", lambda *a, **k: iter([]))

    records = ZoneTransferAdapter()._axfr("192.0.2.1", "empresa.com")

    names_and_types = {(name, rtype) for name, rtype, _ in records}
    assert ("www.empresa.com", "A") in names_and_types
    assert ("internal-db.empresa.com", "A") in names_and_types
    assert ("empresa.com", "SOA") in names_and_types
    assert ("empresa.com", "NS") in names_and_types
    # Nomes vêm absolutos (sem ponto final) — não relativizados à origem.
    a_record = next(r for r in records if r[0] == "www.empresa.com" and r[1] == "A")
    assert a_record[2] == "192.168.1.10"


# --- EmailSecurityAdapter -----------------------------------------------------


def test_email_security_adapter_reports_missing_records(monkeypatch):
    monkeypatch.setattr(EmailSecurityAdapter, "_query_txt", lambda self, name: [])

    results = EmailSecurityAdapter().run("empresa.com", DOMAIN_CONTEXT)

    assert len(results) == 3
    assert all(r.kind == "vulnerability" for r in results)
    assert all(r.data["category"] == "email-security" for r in results)
    assert all(r.data["domain"] == "empresa.com" for r in results)


def test_email_security_adapter_no_findings_for_healthy_domain(monkeypatch):
    def fake_query_txt(self, name):
        if name == "empresa.com":
            return ["v=spf1 include:_spf.google.com -all"]
        if name == "_dmarc.empresa.com":
            return ["v=DMARC1; p=reject;"]
        if name == "default._domainkey.empresa.com":
            return ["v=DKIM1; k=rsa; p=..."]
        return []

    monkeypatch.setattr(EmailSecurityAdapter, "_query_txt", fake_query_txt)

    results = EmailSecurityAdapter().run("empresa.com", DOMAIN_CONTEXT)

    assert results == []


def test_email_security_adapter_ignores_unrelated_txt_records(monkeypatch):
    """TXT records que não começam com v=spf1/v=DMARC1 não contam como SPF/DMARC."""

    def fake_query_txt(self, name):
        if name == "empresa.com":
            return ["google-site-verification=abc123"]  # não é SPF
        return []

    monkeypatch.setattr(EmailSecurityAdapter, "_query_txt", fake_query_txt)

    results = EmailSecurityAdapter().run("empresa.com", DOMAIN_CONTEXT)

    assert any(r.data["title"] == "Registro SPF ausente" for r in results)


def test_email_security_adapter_skips_non_domain_targets(monkeypatch):
    called = []
    monkeypatch.setattr(EmailSecurityAdapter, "_query_txt", lambda self, name: called.append(name))
    assert EmailSecurityAdapter().run("192.168.0.10", DOMAIN_CONTEXT) == []
    assert called == []


def test_email_security_adapter_query_txt_concatenates_fragmented_strings(monkeypatch):
    """TXT records grandes vêm fragmentados em múltiplas strings — precisa concatenar."""

    class _FakeRdata:
        strings = (b"v=spf1 include:_spf.google.com ", b"include:_spf.other.com -all")

    import dns.resolver

    monkeypatch.setattr(dns.resolver, "resolve", lambda name, rtype: [_FakeRdata()])

    result = EmailSecurityAdapter()._query_txt("empresa.com")

    assert result == ["v=spf1 include:_spf.google.com include:_spf.other.com -all"]


# --- WebScanAdapter -----------------------------------------------------

WEB_HOME_HTML = """
<html><body>
<a href="/search?q=test">Search</a>
<a href="/about">About</a>
<form action="/search" method="GET"><input name="q"></form>
</body></html>
"""


def _make_web_fake_fetch(*, netloc="testsite.local:80", sqli_signature=True):
    """Site fake mínimo: home com link/form pesquisáveis, .git/HEAD exposto,
    OPTIONS anunciando PUT, TRACE ecoando, cookie sem flags."""

    def fake_fetch(self, url, *, method="GET", headers=None, allow_redirects=True):
        from urllib.parse import parse_qs, urlsplit

        parts = urlsplit(url)
        if parts.netloc != netloc:
            return None
        path = parts.path
        query = parse_qs(parts.query)
        base_headers = {"Content-Type": "text/html"}
        cookies = [{"name": "sessionid", "secure": False, "httponly": False, "samesite": None}]

        if path == "/" and method == "GET":
            return 200, base_headers, WEB_HOME_HTML, cookies, 0.05
        if path == "/" and method == "OPTIONS":
            return 200, {"Allow": "GET, POST, PUT, OPTIONS"}, "", [], 0.02
        if path == "/" and method == "TRACE":
            marker = (headers or {}).get("X-Byakugan-Probe", "")
            return 200, {}, f"TRACE / HTTP/1.1\r\nX-Byakugan-Probe: {marker}", [], 0.02
        if path == "/about":
            return 200, base_headers, "<html>About us</html>", [], 0.05
        if path == "/search":
            q = query.get("q", [""])[0]
            body = f"<html>You searched: {q}</html>"
            if sqli_signature and "'" in q:
                body = (
                    "You have an error in your SQL syntax; check the manual that "
                    f"corresponds to your MySQL server version near '{q}'"
                )
            return 200, base_headers, body, [], 0.05
        if path == "/.git/HEAD":
            return 200, base_headers, "ref: refs/heads/main\n", [], 0.05
        if path.startswith("/byakugan-") and path.endswith("-notfound"):
            return 404, base_headers, "Not Found", [], 0.05
        return 404, base_headers, "Not Found", [], 0.05

    return fake_fetch


def test_web_scan_end_to_end_detects_all_categories(monkeypatch):
    monkeypatch.setattr(WebScanAdapter, "_fetch", _make_web_fake_fetch())
    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="testsite.local",
        options={"intensity": "normal", "max_pages": 10, "rate_delay": 0},
    )

    results = WebScanAdapter().run("testsite.local", context)

    by_category = {}
    for r in results:
        by_category.setdefault(r.data["category"], []).append(r.data["title"])

    assert "Path sensível acessível: /.git/HEAD" in by_category.get("exposure", [])
    assert any("SQL injection" in t for t in by_category.get("injection", []))
    assert any("XSS" in t for t in by_category.get("injection", []))
    assert any("PUT" in t for t in by_category.get("http-method", []))
    assert any("TRACE" in t for t in by_category.get("http-method", []))
    assert any("Cookie" in t for t in by_category.get("cookie", []))
    assert len(by_category.get("web-headers", [])) == 5  # HTTP: sem HSTS na lista de 6

    assert all(
        r.data.get("description") and r.data.get("evidence") and r.data.get("recommendation")
        for r in results
    )
    assert all(r.data.get("hostname") == "testsite.local" for r in results)
    assert all(r.kind == "vulnerability" for r in results)


def test_web_scan_aggressive_intensity_detects_time_based(monkeypatch):
    def fake_fetch(self, url, *, method="GET", headers=None, allow_redirects=True):
        from urllib.parse import parse_qs, urlsplit

        parts = urlsplit(url)
        if parts.netloc != "testsite.local:80":
            return None
        path = parts.path
        query = parse_qs(parts.query)
        if path == "/" and method == "GET":
            return 200, {"Content-Type": "text/html"}, WEB_HOME_HTML, [], 0.05
        if path == "/" and method in ("OPTIONS", "TRACE"):
            return 200, {}, "", [], 0.02
        if path == "/search":
            q = query.get("q", [""])[0]
            elapsed = 6.0 if "sleep" in q.lower() else 0.05
            return 200, {}, f"searched: {q}", [], elapsed
        return 404, {}, "Not Found", [], 0.05

    monkeypatch.setattr(WebScanAdapter, "_fetch", fake_fetch)
    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="testsite.local",
        options={"intensity": "aggressive", "max_pages": 5, "rate_delay": 0},
    )

    results = WebScanAdapter().run("testsite.local", context)

    assert any("tempo" in r.data["title"].lower() for r in results)


def test_web_scan_safe_intensity_never_tests_time_based(monkeypatch):
    fetch_calls = []

    def fake_fetch(self, url, *, method="GET", headers=None, allow_redirects=True):
        fetch_calls.append(url)
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        if parts.netloc != "testsite.local:80":
            return None
        path = parts.path
        if path == "/" and method == "GET":
            return 200, {"Content-Type": "text/html"}, WEB_HOME_HTML, [], 0.05
        if path == "/" and method in ("OPTIONS", "TRACE"):
            return 200, {}, "", [], 0.02
        if path == "/search":
            return 200, {}, "searched", [], 0.05
        return 404, {}, "Not Found", [], 0.05

    monkeypatch.setattr(WebScanAdapter, "_fetch", fake_fetch)
    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="testsite.local",
        options={"intensity": "safe", "max_pages": 5, "rate_delay": 0},
    )

    WebScanAdapter().run("testsite.local", context)

    assert not any("sleep" in url.lower() for url in fetch_calls)


def test_web_scan_reports_cors_misconfiguration(monkeypatch):
    def fake_fetch(self, url, *, method="GET", headers=None, allow_redirects=True):
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        if parts.netloc != "testsite.local:80":
            return None
        if parts.path == "/" and method == "GET":
            origin = (headers or {}).get("Origin")
            resp_headers = {"Content-Type": "text/html"}
            if origin:
                resp_headers["Access-Control-Allow-Origin"] = origin
                resp_headers["Access-Control-Allow-Credentials"] = "true"
            return 200, resp_headers, "<html>home</html>", [], 0.05
        if parts.path == "/" and method in ("OPTIONS", "TRACE"):
            return 200, {}, "", [], 0.02
        return 404, {}, "Not Found", [], 0.05

    monkeypatch.setattr(WebScanAdapter, "_fetch", fake_fetch)
    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="testsite.local",
        options={"intensity": "normal", "max_pages": 5, "rate_delay": 0},
    )

    results = WebScanAdapter().run("testsite.local", context)

    cors_findings = [r for r in results if r.data["category"] == "cors"]
    assert len(cors_findings) == 1
    assert cors_findings[0].data["severity"] == "high"


def test_web_scan_skips_unreachable_ports(monkeypatch):
    monkeypatch.setattr(WebScanAdapter, "_fetch", lambda self, url, **kwargs: None)
    context = ScanContext(
        scan_id="x", authorized_by="CISO", authorization_scope="empresa.com", options={}
    )
    assert WebScanAdapter().run("empresa.com", context) == []


def test_web_scan_skips_server_error_ports(monkeypatch):
    def fake_fetch(self, url, *, method="GET", headers=None, allow_redirects=True):
        return 500, {}, "Internal Server Error", [], 0.05

    monkeypatch.setattr(WebScanAdapter, "_fetch", fake_fetch)
    context = ScanContext(
        scan_id="x", authorized_by="CISO", authorization_scope="empresa.com", options={}
    )
    assert WebScanAdapter().run("empresa.com", context) == []


def test_web_scan_respects_cancellation():
    from apps.scans.adapters import ScanCancelled

    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="empresa.com",
        options={},
        should_abort=lambda: True,
    )
    with pytest.raises(ScanCancelled):
        WebScanAdapter().run("empresa.com", context)


def test_web_scan_caps_injection_points(monkeypatch):
    """Não deve testar mais que MAX_INJECTION_POINTS parâmetros, mesmo com muitos disponíveis.

    Cada link tem um parâmetro DIFERENTE (p0, p1, ...) com valor original
    "1" — o crawl visita todos eles (uma requisição cada, valor "1"), mas só
    a fase de INJEÇÃO deveria efetivamente testar payloads (valores ≠ "1")
    em, no máximo, MAX_INJECTION_POINTS desses parâmetros.
    """
    many_links = "".join(f'<a href="/page?p{i}=1">L{i}</a>' for i in range(30))
    home_html = f"<html><body>{many_links}</body></html>"

    injected_params: set[str] = set()

    def fake_fetch(self, url, *, method="GET", headers=None, allow_redirects=True):
        from urllib.parse import parse_qs, urlsplit

        parts = urlsplit(url)
        if parts.netloc != "testsite.local:80":
            return None
        if parts.path == "/" and method == "GET":
            return 200, {"Content-Type": "text/html"}, home_html, [], 0.01
        if parts.path == "/" and method in ("OPTIONS", "TRACE"):
            return 200, {}, "", [], 0.01
        if parts.path == "/page":
            params = parse_qs(parts.query)
            for name, values in params.items():
                if values and values[0] != "1":  # "1" é o valor original do crawl
                    injected_params.add(name)
            return 200, {}, "page content", [], 0.01
        return 404, {}, "Not Found", [], 0.01

    monkeypatch.setattr(WebScanAdapter, "_fetch", fake_fetch)
    context = ScanContext(
        scan_id="x",
        authorized_by="CISO",
        authorization_scope="testsite.local",
        options={"intensity": "normal", "max_pages": 40, "rate_delay": 0},
    )

    WebScanAdapter().run("testsite.local", context)

    assert len(injected_params) <= adapters_mod.MAX_INJECTION_POINTS
