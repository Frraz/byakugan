"""Dispatcher dos formatos de relatório: PDF, CSV e JSON (Fase 5).

O PDF profissional (capa, gráficos, numeração) vive em ``pdf.py``; aqui ficam
o CSV — sempre uma linha por finding, independente do ``report_type`` (é um
formato de dados, não narrativo) — e o JSON, que expõe o payload completo de
``payload.py``, além do dispatcher ``render_report``.
"""

from __future__ import annotations

import csv
import io
import json

from apps.scans.models import Scan

from .models import Report
from .payload import build_findings_section, build_report_payload
from .pdf import render_pdf

EXTENSION_BY_FORMAT: dict[str, str] = {
    Report.Format.PDF: "pdf",
    Report.Format.CSV: "csv",
    Report.Format.JSON: "json",
}

CONTENT_TYPE_BY_FORMAT: dict[str, str] = {
    Report.Format.PDF: "application/pdf",
    Report.Format.CSV: "text/csv",
    Report.Format.JSON: "application/json",
}

FINDINGS_CSV_HEADER = [
    "asset",
    "title",
    "category",
    "severity",
    "cvss",
    "cve",
    "description",
    "evidence",
    "recommendation",
]


def render_json(scan: Scan, report_type: str) -> bytes:
    """Payload completo do relatório, em JSON (docs/reporting.md)."""
    payload = build_report_payload(scan, report_type)
    return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")


def render_csv(
    scan: Scan, report_type: str
) -> bytes:  # noqa: ARG001 — assinatura uniforme p/ dispatcher
    """CSV com uma linha por finding — para importação em planilhas/SIEM."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FINDINGS_CSV_HEADER)
    writer.writeheader()
    writer.writerows(build_findings_section(scan))
    return buffer.getvalue().encode("utf-8")


RENDERERS = {
    Report.Format.JSON: render_json,
    Report.Format.CSV: render_csv,
    Report.Format.PDF: render_pdf,
}


def render_report(scan: Scan, report_type: str, format: str) -> bytes:
    """Renderiza o relatório no formato solicitado — dispatcher único do serviço."""
    return RENDERERS[format](scan, report_type)
