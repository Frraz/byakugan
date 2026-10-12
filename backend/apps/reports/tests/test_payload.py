"""Testes de composição do payload de relatório."""

from __future__ import annotations

import pytest

from apps.reports.models import Report
from apps.reports.payload import (
    build_asset_inventory,
    build_attack_narrative,
    build_executive_narrative,
    build_findings_section,
    build_references,
    build_related_knowledge,
    build_report_payload,
    build_scan_metadata,
    build_summary,
    build_top_risks,
)
from apps.reports.tests.factories import make_completed_scan_with_findings
from apps.scans.models import Evidence, Finding

pytestmark = pytest.mark.django_db


def test_build_summary_reflects_findings():
    scan = make_completed_scan_with_findings()
    summary = build_summary(scan)
    assert summary["assets"] == 1
    assert summary["severity"]["high"] == 1
    assert summary["risk_score"] == 7.5
    assert summary["risk_level"] == "low"


def test_build_findings_section_includes_evidence_and_cve():
    scan = make_completed_scan_with_findings()
    finding = scan.findings.first()
    finding.mitre_technique = "T1190"
    finding.save(update_fields=["mitre_technique"])
    findings = build_findings_section(scan)
    assert len(findings) == 1
    assert findings[0]["cve"] == "CVE-2024-1111"
    assert findings[0]["mitre_technique"] == "T1190"
    assert findings[0]["evidence"]
    assert findings[0]["recommendation"]
    assert findings[0]["asset"] == "web01 (192.168.0.10)"


def test_build_findings_section_orders_cvss_nulls_last():
    scan = make_completed_scan_with_findings()
    first = scan.findings.first()
    scan.findings.create(
        asset=first.asset,
        category="network",
        title="Finding sem CVSS",
        severity="info",
        cvss=None,
        description="Descrição.",
        evidence="evidência",
        recommendation="recomendação",
    )
    findings = build_findings_section(scan)
    assert findings[0]["cvss"] == 7.5
    assert findings[-1]["cvss"] is None


def test_build_top_risks_sorted_by_score():
    scan = make_completed_scan_with_findings()
    top = build_top_risks(scan)
    assert len(top) == 1
    assert top[0]["risk_score"] == 7.5


def test_build_asset_inventory_includes_services():
    scan = make_completed_scan_with_findings()
    inventory = build_asset_inventory(scan)
    assert len(inventory) == 1
    assert inventory[0]["os"] == "Ubuntu 24.04"
    assert "443/tcp https" in inventory[0]["services"]


def test_build_scan_metadata_includes_authorization():
    scan = make_completed_scan_with_findings()
    meta = build_scan_metadata(scan)
    assert meta["status"] == "completed"
    assert meta["authorized_by"] == scan.authorized_by


def test_build_executive_narrative_mentions_target_and_risk():
    scan = make_completed_scan_with_findings()
    payload = build_report_payload(scan, Report.ReportType.EXECUTIVE)
    narrative = build_executive_narrative(payload)
    assert scan.target in narrative
    assert "Risk Score" in narrative
    assert "finding" in narrative.lower()


def test_build_references_includes_nvd_link():
    scan = make_completed_scan_with_findings()
    refs = build_references(scan)
    assert len(refs) == 1
    assert refs[0]["cve"] == "CVE-2024-1111"
    assert any(
        "nvd.nist.gov/vuln/detail/CVE-2024-1111" in link for link in refs[0]["links"]
    )
    assert "https://example.com/cve" in refs[0]["links"]


def test_executive_payload_includes_narrative():
    scan = make_completed_scan_with_findings()
    payload = build_report_payload(scan, Report.ReportType.EXECUTIVE)
    assert payload["narrative"]


def test_technical_payload_includes_references():
    scan = make_completed_scan_with_findings()
    payload = build_report_payload(scan, Report.ReportType.TECHNICAL)
    assert len(payload["references"]) == 1


def test_executive_payload_has_top_risks_and_heatmap_not_findings():
    scan = make_completed_scan_with_findings()
    payload = build_report_payload(scan, Report.ReportType.EXECUTIVE)
    assert "top_risks" in payload
    assert "heatmap" in payload
    assert "findings" not in payload


def test_technical_payload_has_findings_and_assets_not_top_risks():
    scan = make_completed_scan_with_findings()
    payload = build_report_payload(scan, Report.ReportType.TECHNICAL)
    assert "findings" in payload
    assert "assets" in payload
    assert "scan" in payload
    assert "top_risks" not in payload


def test_build_related_knowledge_matches_finding_category():
    scan = make_completed_scan_with_findings()  # finding com category="software"
    articles = build_related_knowledge(scan)
    assert len(articles) == 1
    assert articles[0]["slug"] == "outdated-software"
    assert articles[0]["remediation_steps"]


def test_build_related_knowledge_deduplicates_repeated_category():
    from apps.assets.models import Asset
    from apps.scans.models import Finding, Vulnerability

    scan = make_completed_scan_with_findings()
    asset = Asset.objects.create(ip="192.168.0.20", hostname="web02")
    vulnerability = Vulnerability.objects.create(
        cve="CVE-2024-2222", title="Outra vuln", severity="medium", description="d"
    )
    Finding.objects.create(
        scan=scan,
        asset=asset,
        vulnerability=vulnerability,
        category="software",  # mesma categoria do finding original
        title="CVE-2024-2222 em apache",
        severity="medium",
        description="d",
        evidence="e",
        recommendation="r",
    )

    articles = build_related_knowledge(scan)

    assert len(articles) == 1  # não duplica o mesmo artigo


def test_technical_payload_includes_knowledge_articles():
    scan = make_completed_scan_with_findings()
    payload = build_report_payload(scan, Report.ReportType.TECHNICAL)
    assert "knowledge_articles" in payload
    assert payload["knowledge_articles"][0]["slug"] == "outdated-software"


def test_executive_payload_does_not_include_knowledge_articles():
    scan = make_completed_scan_with_findings()
    payload = build_report_payload(scan, Report.ReportType.EXECUTIVE)
    assert "knowledge_articles" not in payload


# --- Attack narrative (Fase C12) --------------------------------------------


def _proven_evidence(scan, *, playbook_key, impact_level, proof="prova", asset=None):
    """Cria um Finding + Evidence `proven` prontos para a narrativa de ataque."""
    asset = asset or scan.findings.first().asset
    finding = Finding.objects.create(
        scan=scan,
        asset=asset,
        category="injection",
        title=f"Achado {playbook_key}",
        severity="critical",
        description="d",
        evidence="e",
        recommendation="r",
        playbook_key=playbook_key,
    )
    return Evidence.objects.create(
        finding=finding,
        scan=scan,
        asset=asset,
        playbook_key=playbook_key,
        status=Evidence.Status.PROVEN,
        impact_level=impact_level,
        proof=proof,
    )


def test_build_attack_narrative_empty_without_proven_evidence():
    scan = make_completed_scan_with_findings()
    assert build_attack_narrative(scan) == []


def test_build_attack_narrative_ignores_non_proven_evidence():
    scan = make_completed_scan_with_findings()
    asset = scan.findings.first().asset
    finding = Finding.objects.create(
        scan=scan,
        asset=asset,
        category="injection",
        title="Tentativa sem prova",
        severity="high",
        description="d",
        evidence="e",
        recommendation="r",
        playbook_key="injection.sqli-error",
    )
    Evidence.objects.create(
        finding=finding,
        scan=scan,
        asset=asset,
        playbook_key="injection.sqli-error",
        status=Evidence.Status.ATTEMPTED,
        impact_level="none",
    )
    assert build_attack_narrative(scan) == []


def test_build_attack_narrative_includes_proven_step_with_mitre_technique():
    scan = make_completed_scan_with_findings()
    _proven_evidence(
        scan,
        playbook_key="injection.sqli-error",
        impact_level="db-read",
        proof="Versão: 8.0",
    )

    narrative = build_attack_narrative(scan)

    assert len(narrative) == 1
    entry = narrative[0]
    assert entry["asset"] == "web01 (192.168.0.10)"
    assert entry["max_impact"] == "db-read"
    assert entry["mitre_techniques"] == ["T1190"]
    assert entry["steps"][0]["playbook_key"] == "injection.sqli-error"
    assert entry["steps"][0]["proof"] == "Versão: 8.0"
    assert (
        entry["steps"][0]["mitre_technique_name"] == "Exploit Public-Facing Application"
    )


def test_build_attack_narrative_orders_steps_by_impact_severity():
    scan = make_completed_scan_with_findings()
    _proven_evidence(
        scan, playbook_key="injection.ssrf", impact_level="info-disclosure"
    )
    _proven_evidence(scan, playbook_key="injection.sqli-error", impact_level="db-read")

    narrative = build_attack_narrative(scan)

    assert len(narrative) == 1
    impacts = [s["impact_level"] for s in narrative[0]["steps"]]
    assert impacts == ["db-read", "info-disclosure"]  # mais grave primeiro


def test_build_attack_narrative_orders_assets_by_max_impact_descending():
    scan = make_completed_scan_with_findings()
    from apps.assets.models import Asset

    other_asset = Asset.objects.create(ip="192.168.0.20", hostname="web02")
    _proven_evidence(scan, playbook_key="injection.xss", impact_level="session")
    _proven_evidence(
        scan,
        playbook_key="injection.command-injection",
        impact_level="rce",
        asset=other_asset,
    )

    narrative = build_attack_narrative(scan)

    assert [n["asset"] for n in narrative] == [
        "web02 (192.168.0.20)",
        "web01 (192.168.0.10)",
    ]


def test_build_attack_narrative_surfaces_applicable_chain():
    scan = make_completed_scan_with_findings()
    asset = scan.findings.first().asset
    _proven_evidence(scan, playbook_key="injection.xss", impact_level="session")
    # misconfig.weak-csp só precisa existir como Finding (não precisa de
    # Evidence própria) para a cadeia xss + CSP fraca se formar no ativo.
    Finding.objects.create(
        scan=scan,
        asset=asset,
        category="web-headers",
        title="CSP fraca",
        severity="high",
        description="d",
        evidence="e",
        recommendation="r",
        playbook_key="misconfig.weak-csp",
    )

    narrative = build_attack_narrative(scan)

    assert len(narrative) == 1
    assert narrative[0]["chains"][0]["chain_key"] == "xss-unmitigated-by-csp"


def test_technical_payload_includes_attack_narrative():
    scan = make_completed_scan_with_findings()
    _proven_evidence(scan, playbook_key="injection.sqli-error", impact_level="db-read")
    payload = build_report_payload(scan, Report.ReportType.TECHNICAL)
    assert len(payload["attack_narrative"]) == 1


def test_executive_payload_does_not_include_attack_narrative():
    scan = make_completed_scan_with_findings()
    payload = build_report_payload(scan, Report.ReportType.EXECUTIVE)
    assert "attack_narrative" not in payload


def test_render_pdf_with_attack_narrative_section_returns_pdf():
    from apps.reports.pdf import render_pdf

    scan = make_completed_scan_with_findings()
    _proven_evidence(scan, playbook_key="injection.sqli-error", impact_level="db-read")
    for report_type in (Report.ReportType.EXECUTIVE, Report.ReportType.TECHNICAL):
        data = render_pdf(scan, report_type)
        assert data[:5] == b"%PDF-"
        assert len(data) > 1000
