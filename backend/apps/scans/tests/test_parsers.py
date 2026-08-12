"""Testes de normalização/persistência de resultados (inventário)."""

from __future__ import annotations

import pytest

from apps.assets.models import Asset, DnsRecord, Service, Technology
from apps.scans.adapters import RawResult
from apps.scans.models import Finding, Vulnerability
from apps.scans.parsers import compute_dedup_key, persist_findings, persist_results
from apps.scans.tests.factories import ScanFactory

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


def _vuln_result(asset_id, cve="CVE-2024-1111", **extra):
    return RawResult(
        kind="vulnerability",
        data={
            "asset_id": str(asset_id),
            "cve": cve,
            "title": f"{cve} em nginx 1.18.0",
            "severity": "high",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/...",
            "description": "Descrição da vulnerabilidade.",
            "references": ["https://example.com/cve"],
            "category": "software",
            "evidence": "nginx 1.18.0 identificado via service (porta 443).",
            "recommendation": "Atualizar nginx.",
            "product": "nginx",
            "product_version": "1.18.0",
            **extra,
        },
    )


def test_persist_findings_creates_finding_and_vulnerability():
    asset = Asset.objects.create(ip="192.168.0.10")
    scan = ScanFactory()

    summary = persist_findings(scan, [_vuln_result(asset.id)])

    assert summary.findings == 1
    assert summary.vulnerabilities == 1
    finding = Finding.objects.get()
    assert finding.scan_id == scan.id
    assert finding.asset_id == asset.id
    assert finding.vulnerability.cve == "CVE-2024-1111"
    assert finding.severity == "high"
    assert finding.description
    assert finding.evidence
    assert finding.recommendation


def test_persist_findings_reuses_existing_vulnerability_across_scans():
    asset = Asset.objects.create(ip="192.168.0.10")
    scan1 = ScanFactory()
    scan2 = ScanFactory()

    persist_findings(scan1, [_vuln_result(asset.id)])
    summary2 = persist_findings(scan2, [_vuln_result(asset.id)])

    assert summary2.vulnerabilities == 0  # catálogo reaproveitado
    assert summary2.findings == 1
    assert Vulnerability.objects.count() == 1
    assert (
        Finding.objects.filter(vulnerability__cve="CVE-2024-1111").count() == 2
    )  # imutável por scan


def test_persist_findings_ignores_non_vulnerability_results():
    scan = ScanFactory()
    raw = [RawResult(kind="service", data={"ip": "192.168.0.10", "port": 22})]

    summary = persist_findings(scan, raw)

    assert summary.findings == 0
    assert not Finding.objects.exists()


def test_persist_findings_creates_finding_without_cve():
    """Adapters de TLS/web/DNS não têm CVE — o finding fica com vulnerability=None."""
    asset = Asset.objects.create(ip="192.168.0.10")
    scan = ScanFactory()
    raw = [
        RawResult(
            kind="vulnerability",
            data={
                "asset_id": str(asset.id),
                "title": "TLSv1 habilitado",
                "severity": "medium",
                "category": "tls",
                "description": "O serviço aceita conexões TLSv1, protocolo obsoleto.",
                "evidence": "TLSv1 negociado na porta 443.",
                "recommendation": "Desabilitar TLSv1/1.1.",
                # sem "cve"
            },
        )
    ]

    summary = persist_findings(scan, raw)

    assert summary.findings == 1
    assert summary.vulnerabilities == 0
    finding = Finding.objects.get()
    assert finding.vulnerability is None
    assert finding.category == "tls"
    assert Vulnerability.objects.count() == 0


def test_service_with_banner_grab_enriches_existing_service():
    """Reexecução com banner grab (Fase 1) completa product/version sem duplicar."""
    asset = Asset.objects.create(ip="192.168.0.10")
    Service.objects.create(asset=asset, port=22, protocol="tcp", service_name="ssh")

    summary = persist_results(
        [
            RawResult(
                kind="service",
                data={
                    "ip": "192.168.0.10",
                    "port": 22,
                    "protocol": "tcp",
                    "service_name": "ssh",
                    "product": "OpenSSH",
                    "version": "8.2p1",
                },
            )
        ]
    )

    assert summary.services == 0  # não é uma criação nova
    service = Service.objects.get(port=22)
    assert service.product == "OpenSSH"
    assert service.version == "8.2p1"


def test_service_enrichment_does_not_overwrite_known_product():
    asset = Asset.objects.create(ip="192.168.0.10")
    Service.objects.create(
        asset=asset, port=22, protocol="tcp", service_name="ssh", product="Dropbear", version="1.0"
    )

    persist_results(
        [
            RawResult(
                kind="service",
                data={
                    "ip": "192.168.0.10",
                    "port": 22,
                    "protocol": "tcp",
                    "service_name": "ssh",
                    "product": "OpenSSH",
                    "version": "8.2p1",
                },
            )
        ]
    )

    service = Service.objects.get(port=22)
    assert service.product == "Dropbear"  # não sobrescreve o já conhecido


# --- Findings sem asset_id (adapters de fase "profile", ex.: TlsAdapter) ----


def test_persist_findings_resolves_asset_by_ip_when_asset_id_absent():
    """TlsAdapter roda na fase profile, antes de qualquer Asset existir —
    persist_findings precisa criar/achar o ativo pela chave natural, como
    persist_results já faz."""
    scan = ScanFactory()
    raw = [
        RawResult(
            kind="vulnerability",
            data={
                "ip": "192.168.0.40",
                "hostname": "tls01",
                "title": "Certificado TLS expirado",
                "severity": "high",
                "category": "certificate",
                "description": "O certificado expirou.",
                "evidence": "notAfter=2020-01-01.",
                "recommendation": "Renovar o certificado.",
            },
        )
    ]

    summary = persist_findings(scan, raw)

    assert summary.findings == 1
    finding = Finding.objects.get()
    assert finding.asset.ip == "192.168.0.40"
    assert finding.asset.hostname == "tls01"
    assert finding.vulnerability is None


def test_persist_findings_without_asset_id_reuses_existing_asset():
    """Não deve criar um segundo Asset se um já existe pela mesma chave natural."""
    existing = Asset.objects.create(ip="192.168.0.50", hostname="web01")
    scan = ScanFactory()
    raw = [
        RawResult(
            kind="vulnerability",
            data={
                "ip": "192.168.0.50",
                "hostname": "web01",
                "title": "Cipher TLS fraco negociado",
                "severity": "high",
                "category": "tls",
                "description": "d",
                "evidence": "e",
                "recommendation": "r",
            },
        )
    ]

    persist_findings(scan, raw)

    assert Asset.objects.count() == 1
    assert Finding.objects.get().asset_id == existing.id


def test_persist_findings_prefers_asset_id_over_natural_key_when_both_present():
    explicit_asset = Asset.objects.create(ip="192.168.0.60")
    Asset.objects.create(ip="192.168.0.61", hostname="other")
    scan = ScanFactory()
    raw = [
        RawResult(
            kind="vulnerability",
            data={
                "asset_id": str(explicit_asset.id),
                "ip": "192.168.0.61",  # deveria ser ignorado — asset_id manda
                "title": "x",
                "severity": "low",
                "category": "software",
                "description": "d",
                "evidence": "e",
                "recommendation": "r",
            },
        )
    ]

    persist_findings(scan, raw)

    assert Finding.objects.get().asset_id == explicit_asset.id


# --- dns_record (Fase 3: corrige o kind antes descartado) --------------------


def test_persist_creates_dns_record():
    raw = [
        RawResult(
            kind="dns_record",
            data={"domain": "empresa.com", "record_type": "MX", "value": "10 mail.empresa.com."},
        )
    ]

    summary = persist_results(raw)

    assert summary.dns_records == 1
    assert summary.assets == 1
    record = DnsRecord.objects.get()
    assert record.record_type == "MX"
    assert record.value == "10 mail.empresa.com."
    assert record.asset.domain == "empresa.com"


def test_persist_dns_record_is_idempotent():
    raw = [
        RawResult(
            kind="dns_record",
            data={"domain": "empresa.com", "record_type": "TXT", "value": "v=spf1 -all"},
        )
    ]
    persist_results(raw)
    persist_results(raw)

    assert DnsRecord.objects.count() == 1


def test_persist_dns_record_reuses_existing_domain_asset():
    existing = Asset.objects.create(domain="empresa.com")
    raw = [
        RawResult(
            kind="dns_record",
            data={"domain": "empresa.com", "record_type": "NS", "value": "ns1.empresa.com."},
        )
    ]

    persist_results(raw)

    assert Asset.objects.count() == 1
    assert DnsRecord.objects.get().asset_id == existing.id


def test_persist_multiple_dns_records_for_same_domain():
    raw = [
        RawResult(
            kind="dns_record",
            data={"domain": "empresa.com", "record_type": "NS", "value": "ns1.empresa.com."},
        ),
        RawResult(
            kind="dns_record",
            data={"domain": "empresa.com", "record_type": "NS", "value": "ns2.empresa.com."},
        ),
    ]

    summary = persist_results(raw)

    assert summary.dns_records == 2
    assert summary.assets == 1  # mesmo domínio — um único Asset
    assert DnsRecord.objects.count() == 2


# --- dedup_key (Fase 5: correlação/triagem) -----------------------------------


def test_compute_dedup_key_is_deterministic():
    key1 = compute_dedup_key(asset_id="abc", category="tls", title="TLSv1 habilitado")
    key2 = compute_dedup_key(asset_id="abc", category="tls", title="TLSv1 habilitado")
    assert key1 == key2
    assert len(key1) == 64  # sha256 hexdigest


def test_compute_dedup_key_normalizes_title_case_and_spacing():
    key1 = compute_dedup_key(asset_id="abc", category="tls", title="TLSv1 Habilitado")
    key2 = compute_dedup_key(asset_id="abc", category="tls", title="  tlsv1   habilitado  ")
    assert key1 == key2


def test_compute_dedup_key_differs_on_asset_category_or_title():
    base = compute_dedup_key(asset_id="abc", category="tls", title="TLSv1 habilitado")
    assert compute_dedup_key(asset_id="xyz", category="tls", title="TLSv1 habilitado") != base
    assert compute_dedup_key(asset_id="abc", category="dns", title="TLSv1 habilitado") != base
    assert compute_dedup_key(asset_id="abc", category="tls", title="TLSv1.1 habilitado") != base


def test_persist_findings_computes_dedup_key():
    asset = Asset.objects.create(ip="192.168.0.10")
    scan = ScanFactory()

    persist_findings(scan, [_vuln_result(asset.id)])

    finding = Finding.objects.get()
    expected = compute_dedup_key(asset_id=str(asset.id), category="software", title=finding.title)
    assert finding.dedup_key == expected


def test_persist_findings_reruns_share_same_dedup_key():
    """Reexecutar o mesmo scan sobre o mesmo alvo gera achados com o mesmo dedup_key,
    apesar de serem Finding rows distintos (imutabilidade — RN003)."""
    asset = Asset.objects.create(ip="192.168.0.10")
    scan1 = ScanFactory()
    scan2 = ScanFactory()

    persist_findings(scan1, [_vuln_result(asset.id)])
    persist_findings(scan2, [_vuln_result(asset.id)])

    dedup_keys = set(Finding.objects.values_list("dedup_key", flat=True))
    assert len(dedup_keys) == 1
    assert Finding.objects.count() == 2
