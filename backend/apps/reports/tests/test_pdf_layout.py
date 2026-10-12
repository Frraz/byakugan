"""Regressão de conteúdo longo, fontes e markup literal no PDF (RN008/RN012)."""

from __future__ import annotations

import pytest

from apps.reports.models import Report
from apps.reports.pdf import render_pdf
from apps.reports.tests.factories import make_completed_scan_with_findings

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    "report_type", [Report.ReportType.EXECUTIVE, Report.ReportType.TECHNICAL]
)
def test_pdf_embeds_fonts_and_handles_long_target_and_literal_markup(report_type):
    """Conteúdo observado não pode virar markup nem exceder o layout de uma linha."""
    scan = make_completed_scan_with_findings()
    scan.target = "segmento-" * 28 + ".example.test"
    scan.authorization_scope = scan.target
    scan.save(update_fields=["target", "authorization_scope"])
    finding = scan.findings.first()
    finding.title = "Configuração <script> & cabeçalhos de segurança"
    finding.evidence = (
        "Amostra literal: <para><b>não interpretar</b></para> & </font>\n" * 120
    )
    finding.description = (
        "Descrição com acentuação: ação, evidência, configuração.\n" * 60
    )
    finding.recommendation = "Revisar configuração " + "identificador" * 300
    finding.save(update_fields=["title", "evidence", "description", "recommendation"])
    content = render_pdf(scan, report_type)
    assert content.startswith(b"%PDF")
    assert b"/FontFile2" in content  # Fonte TrueType embutida, independente da máquina.


def test_technical_pdf_renders_oversized_inventory_row():
    """Serviços/textos extensos podem continuar na página seguinte sem LayoutError."""
    scan = make_completed_scan_with_findings()
    finding = scan.findings.first()
    finding.asset.os = "Linux " * 2500
    finding.asset.save(update_fields=["os"])
    assert render_pdf(scan, Report.ReportType.TECHNICAL).startswith(b"%PDF")
