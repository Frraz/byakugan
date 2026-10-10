"""Testes de integração da classificação OWASP: persistência + endpoint de cobertura."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.scans.adapters import RawResult
from apps.scans.models import Finding, Scan
from apps.scans.parsers import persist_findings
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


def _vuln(**over) -> RawResult:
    data = {
        "ip": "192.168.0.10",
        "host": "web01",
        "title": "Possível SQL injection (baseada em erro)",
        "severity": "critical",
        "category": "injection",
        "description": "desc",
        "evidence": "URL: http://web01/x?id=1 | Parâmetro: 'id' | erro",
        "recommendation": "rec",
        "playbook_key": "injection.sqli-error",
    }
    data.update(over)
    return RawResult(kind="vulnerability", data=data)


def test_persist_findings_enriches_owasp_and_cwe():
    scan = ScanFactory(scan_type=Scan.ScanType.VULNERABILITY, status=Scan.Status.COMPLETED)
    persist_findings(scan, [_vuln()])
    finding = Finding.objects.get()
    assert finding.owasp_2021 == "A03"
    assert finding.owasp_2025 == "A05"
    assert finding.cwe == "CWE-89"


def test_persist_findings_ssrf_diverges_between_editions():
    scan = ScanFactory(scan_type=Scan.ScanType.VULNERABILITY, status=Scan.Status.COMPLETED)
    persist_findings(
        scan,
        [_vuln(title="SSRF possível", playbook_key="injection.ssrf", category="injection")],
    )
    finding = Finding.objects.get()
    assert (finding.owasp_2021, finding.owasp_2025) == ("A10", "A01")


def test_owasp_coverage_endpoint(analyst_client):
    scan = ScanFactory(scan_type=Scan.ScanType.FULL, status=Scan.Status.COMPLETED)
    persist_findings(scan, [_vuln()])

    url = reverse("scans:scan-owasp-coverage", args=[scan.id])
    resp = analyst_client.get(url)
    assert resp.status_code == 200

    data = resp.json()
    assert len(data["2021"]) == 10 and len(data["2025"]) == 10
    a03 = next(r for r in data["2021"] if r["code"] == "A03")
    assert a03["findings"] == 1
    assert a03["highest_severity"] == "critical"
    # A04:2021 (Insecure Design) reportado como cobertura limitada, não falso "ok".
    a04 = next(r for r in data["2021"] if r["code"] == "A04")
    assert a04["status"] == "limited"


def test_finding_serializer_exposes_owasp_fields(analyst_client):
    scan = ScanFactory(scan_type=Scan.ScanType.VULNERABILITY, status=Scan.Status.COMPLETED)
    persist_findings(scan, [_vuln()])

    url = reverse("scans:scan-findings", args=[scan.id])
    resp = analyst_client.get(url)
    assert resp.status_code == 200
    row = resp.json()[0]
    assert row["owasp_2021"] == "A03"
    assert row["owasp_2025"] == "A05"
    assert row["cwe"] == "CWE-89"


# --- MITRE ATT&CK (terceira dimensão de classificação) ----------------------


def test_persist_findings_enriches_mitre_technique():
    scan = ScanFactory(scan_type=Scan.ScanType.VULNERABILITY, status=Scan.Status.COMPLETED)
    persist_findings(scan, [_vuln()])
    finding = Finding.objects.get()
    assert finding.mitre_technique == "T1190"


def test_persist_findings_leaves_mitre_technique_blank_when_unmapped():
    scan = ScanFactory(scan_type=Scan.ScanType.VULNERABILITY, status=Scan.Status.COMPLETED)
    persist_findings(
        scan,
        [_vuln(title="CSP fraca", playbook_key="misconfig.weak-csp", category="web-headers")],
    )
    finding = Finding.objects.get()
    assert finding.mitre_technique == ""


def test_finding_serializer_exposes_mitre_technique(analyst_client):
    scan = ScanFactory(scan_type=Scan.ScanType.VULNERABILITY, status=Scan.Status.COMPLETED)
    persist_findings(scan, [_vuln()])

    url = reverse("scans:scan-findings", args=[scan.id])
    resp = analyst_client.get(url)
    assert resp.json()[0]["mitre_technique"] == "T1190"


def test_findings_filterable_by_mitre_technique(analyst_client):
    scan = ScanFactory(scan_type=Scan.ScanType.VULNERABILITY, status=Scan.Status.COMPLETED)
    persist_findings(
        scan,
        [
            _vuln(),  # T1190
            _vuln(
                title="Command injection",
                playbook_key="injection.command-injection",
                category="injection",
            ),  # T1059
        ],
    )

    resp = analyst_client.get(reverse("scans:finding-list"), {"mitre_technique": "T1059"})
    assert resp.data["count"] == 1
    assert resp.data["results"][0]["title"] == "Command injection"


def test_findings_grouped_includes_mitre_technique(analyst_client):
    scan = ScanFactory(scan_type=Scan.ScanType.VULNERABILITY, status=Scan.Status.COMPLETED)
    persist_findings(scan, [_vuln()])

    resp = analyst_client.get(reverse("scans:finding-grouped"))
    assert resp.data["results"][0]["mitre_technique"] == "T1190"
