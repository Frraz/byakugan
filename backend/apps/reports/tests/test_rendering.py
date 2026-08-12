"""Testes de renderização dos formatos de relatório (JSON/CSV/PDF)."""

from __future__ import annotations

import csv
import io
import json

import pytest

from apps.reports.models import Report
from apps.reports.rendering import render_csv, render_json, render_pdf, render_report
from apps.reports.tests.factories import make_completed_scan_with_findings
from apps.scans.models import Scan
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


def test_render_json_matches_payload_structure():
    scan = make_completed_scan_with_findings()
    content = render_json(scan, Report.ReportType.TECHNICAL)
    data = json.loads(content)
    assert data["scan_id"] == str(scan.id)
    assert len(data["findings"]) == 1


def test_render_csv_has_one_row_per_finding():
    scan = make_completed_scan_with_findings()
    content = render_csv(scan, Report.ReportType.TECHNICAL)
    rows = list(csv.DictReader(io.StringIO(content.decode("utf-8"))))
    assert len(rows) == 1
    assert rows[0]["cve"] == "CVE-2024-1111"
    assert rows[0]["severity"] == "high"


def test_render_csv_ignores_report_type():
    """CSV é sempre a lista de findings, independente do report_type."""
    scan = make_completed_scan_with_findings()
    executive = render_csv(scan, Report.ReportType.EXECUTIVE)
    technical = render_csv(scan, Report.ReportType.TECHNICAL)
    assert executive == technical


def test_render_pdf_produces_valid_pdf_bytes():
    scan = make_completed_scan_with_findings()
    content = render_pdf(scan, Report.ReportType.EXECUTIVE)
    assert content.startswith(b"%PDF")
    assert len(content) > 500


def test_render_pdf_technical_report():
    scan = make_completed_scan_with_findings()
    content = render_pdf(scan, Report.ReportType.TECHNICAL)
    assert content.startswith(b"%PDF")


def test_render_pdf_handles_scan_without_findings():
    scan = ScanFactory(status=Scan.Status.COMPLETED)
    content = render_pdf(scan, Report.ReportType.EXECUTIVE)
    assert content.startswith(b"%PDF")


def test_render_report_dispatches_by_format():
    scan = make_completed_scan_with_findings()
    assert render_report(scan, Report.ReportType.TECHNICAL, Report.Format.JSON).startswith(b"{")
    assert render_report(scan, Report.ReportType.TECHNICAL, Report.Format.PDF).startswith(b"%PDF")
