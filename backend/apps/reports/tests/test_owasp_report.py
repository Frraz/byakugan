"""Testes da seção de cobertura OWASP no relatório (payload + PDF)."""

from __future__ import annotations

import pytest

from apps.reports.models import Report
from apps.reports.payload import build_owasp_coverage, build_report_payload
from apps.reports.pdf import render_pdf
from apps.scans.adapters import RawResult
from apps.scans.models import Scan
from apps.scans.parsers import persist_findings
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


def _scan_with_owasp_finding() -> Scan:
    scan = ScanFactory(scan_type=Scan.ScanType.FULL, status=Scan.Status.COMPLETED)
    persist_findings(
        scan,
        [
            RawResult(
                kind="vulnerability",
                data={
                    "ip": "192.168.0.10",
                    "host": "web01",
                    "title": "Possível SQL injection (baseada em erro)",
                    "severity": "critical",
                    "category": "injection",
                    "description": "desc",
                    "evidence": "URL: http://web01/x?id=1 | Parâmetro: 'id' | erro",
                    "recommendation": "rec",
                    "playbook_key": "injection.sqli-error",
                },
            )
        ],
    )
    return scan


def test_build_owasp_coverage_matrix():
    scan = _scan_with_owasp_finding()
    coverage = build_owasp_coverage(scan)
    assert len(coverage["2021"]) == 10 and len(coverage["2025"]) == 10
    a03 = next(r for r in coverage["2021"] if r["code"] == "A03")
    assert a03["findings"] == 1


def test_report_payload_includes_owasp_coverage_both_types():
    scan = _scan_with_owasp_finding()
    executive = build_report_payload(scan, Report.ReportType.EXECUTIVE)
    technical = build_report_payload(scan, Report.ReportType.TECHNICAL)
    assert "owasp_coverage" in executive
    assert "owasp_coverage" in technical
    # o finding técnico carrega a classificação OWASP/CWE
    finding = technical["findings"][0]
    assert finding["owasp_2021"] == "A03" and finding["cwe"] == "CWE-89"


def test_render_pdf_with_owasp_section_returns_pdf():
    scan = _scan_with_owasp_finding()
    for report_type in (Report.ReportType.EXECUTIVE, Report.ReportType.TECHNICAL):
        data = render_pdf(scan, report_type)
        assert data[:5] == b"%PDF-"
        assert len(data) > 1000
