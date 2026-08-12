"""Testes de composição do payload de relatório."""

from __future__ import annotations

import pytest

from apps.reports.models import Report
from apps.reports.payload import (
    build_asset_inventory,
    build_findings_section,
    build_related_knowledge,
    build_report_payload,
    build_scan_metadata,
    build_summary,
    build_top_risks,
)
from apps.reports.tests.factories import make_completed_scan_with_findings

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
    findings = build_findings_section(scan)
    assert len(findings) == 1
    assert findings[0]["cve"] == "CVE-2024-1111"
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
