"""Testes de composição do payload de relatório."""

from __future__ import annotations

import pytest

from apps.reports.models import Report
from apps.reports.payload import (
    build_asset_inventory,
    build_findings_section,
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
