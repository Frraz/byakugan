"""Renderização dos formatos de relatório: PDF, CSV e JSON (Fase 5).

PDF via ``reportlab`` (puro Python, sem dependências de sistema — ao
contrário de WeasyPrint/Pango, roda direto no Dockerfile atual). CSV é
sempre uma linha por finding (independente do ``report_type`` — é um
formato de dados, não narrativo). JSON expõe o payload completo de
``payload.py``.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from apps.scans.models import Scan

from .models import Report
from .payload import build_findings_section, build_report_payload

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


_STYLES = getSampleStyleSheet()
_BODY_STYLE = ParagraphStyle("body-small", parent=_STYLES["BodyText"], fontSize=8, leading=10)
_FOOTER_STYLE = ParagraphStyle(
    "footer", parent=_STYLES["Normal"], fontSize=7, textColor=colors.grey
)

# Mesma paleta de severidade do frontend (docs/ui.md).
_SEVERITY_COLORS: dict[str, colors.Color] = {
    "critical": colors.HexColor("#EF4444"),
    "high": colors.HexColor("#F97316"),
    "medium": colors.HexColor("#F59E0B"),
    "low": colors.HexColor("#00D4FF"),
    "info": colors.HexColor("#64748B"),
}


def _p(text: str | None) -> Paragraph:
    return Paragraph(text or "—", _BODY_STYLE)


def _grid_style(*, header: bool) -> list[tuple]:
    style = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111A2E")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    return style


def _table(rows: list[list], col_widths: list[float], *, header: bool = True) -> Table:
    table = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
    table.setStyle(TableStyle(_grid_style(header=header)))
    return table


def _summary_table(summary: dict[str, Any]) -> Table:
    severity = summary["severity"]
    rows = [
        ["Ativos analisados", str(summary["assets"])],
        ["Risk Score", f"{summary['risk_score']}/100 ({summary['risk_level']})"],
        ["Críticas", str(severity["critical"])],
        ["Altas", str(severity["high"])],
        ["Médias", str(severity["medium"])],
        ["Baixas", str(severity["low"])],
        ["Informativas", str(severity["info"])],
    ]
    table = Table(rows, colWidths=[6 * cm, 6 * cm])
    style = [
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#111A2E")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    table.setStyle(TableStyle(style))
    return table


def _executive_story(payload: dict[str, Any]) -> list:
    story = [
        Paragraph("Resumo executivo", _STYLES["Heading2"]),
        _summary_table(payload["summary"]),
        Spacer(1, 0.5 * cm),
    ]

    story.append(Paragraph("Top riscos priorizados", _STYLES["Heading2"]))
    rows = [["Ativo", "Risk Score", "Nível", "Findings"]]
    for asset in payload["top_risks"]:
        label = asset["hostname"] or asset["ip"] or asset["domain"] or asset["asset"]
        rows.append(
            [label, f"{asset['risk_score']}/100", asset["risk_level"], str(asset["findings"])]
        )
    if len(rows) == 1:
        rows.append(["—", "—", "—", "—"])
    story += [_table(rows, [6 * cm, 3 * cm, 3 * cm, 3 * cm]), Spacer(1, 0.5 * cm)]

    story.append(Paragraph("Heatmap por categoria", _STYLES["Heading2"]))
    heatmap_rows = [["Categoria", "Severidade", "Findings"]]
    for cell in payload["heatmap"]:
        heatmap_rows.append([cell["category"], cell["severity"], str(cell["count"])])
    if len(heatmap_rows) == 1:
        heatmap_rows.append(["—", "—", "—"])
    story.append(_table(heatmap_rows, [6 * cm, 4 * cm, 4 * cm]))
    return story


def _technical_story(payload: dict[str, Any]) -> list:
    story = [
        Paragraph("Resumo", _STYLES["Heading2"]),
        _summary_table(payload["summary"]),
        Spacer(1, 0.5 * cm),
    ]

    meta = payload["scan"]
    story.append(Paragraph("Metadados do scan", _STYLES["Heading2"]))
    meta_rows = [
        ["Tipo", meta["scan_type"]],
        ["Status", meta["status"]],
        ["Autorizado por", meta["authorized_by"]],
        ["Escopo", meta["authorization_scope"]],
        ["Iniciado em", meta["started_at"] or "—"],
        ["Finalizado em", meta["finished_at"] or "—"],
    ]
    story += [_table(meta_rows, [4 * cm, 10 * cm], header=False), Spacer(1, 0.5 * cm)]

    story.append(Paragraph("Inventário de ativos", _STYLES["Heading2"]))
    asset_rows = [["Ativo", "SO", "Serviços"]]
    for asset in payload["assets"]:
        asset_rows.append([asset["asset"], asset["os"] or "—", ", ".join(asset["services"]) or "—"])
    if len(asset_rows) == 1:
        asset_rows.append(["—", "—", "—"])
    story += [_table(asset_rows, [5 * cm, 3 * cm, 6 * cm]), Spacer(1, 0.5 * cm)]

    story.append(Paragraph("Findings", _STYLES["Heading2"]))
    findings = payload["findings"]
    finding_rows = [["Ativo", "Título", "Severidade", "CVSS", "Evidência", "Recomendação"]]
    for f in findings:
        finding_rows.append(
            [
                _p(f["asset"]),
                _p(f["title"]),
                f["severity"],
                str(f["cvss"]) if f["cvss"] is not None else "—",
                _p(f["evidence"]),
                _p(f["recommendation"]),
            ]
        )
    if len(finding_rows) == 1:
        finding_rows.append(["—", "—", "—", "—", "—", "—"])

    finding_table = Table(
        finding_rows, colWidths=[3 * cm, 3.5 * cm, 2 * cm, 1.5 * cm, 4 * cm, 4 * cm], repeatRows=1
    )
    style = _grid_style(header=True)
    # Destaca a coluna de severidade com a mesma paleta do frontend (docs/ui.md).
    for i, f in enumerate(findings, start=1):
        color = _SEVERITY_COLORS.get(f["severity"])
        if color:
            style.append(("TEXTCOLOR", (2, i), (2, i), color))
            style.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    finding_table.setStyle(TableStyle(style))
    story.append(finding_table)

    articles = payload.get("knowledge_articles", [])
    if articles:
        story += [
            Spacer(1, 0.5 * cm),
            Paragraph("Conhecimento relacionado (remediação)", _STYLES["Heading2"]),
        ]
        for article in articles:
            story.append(Paragraph(article["title"], _STYLES["Heading3"]))
            story.append(_p(article["summary"]))
            steps = "<br/>".join(
                f"{i}. {step}" for i, step in enumerate(article["remediation_steps"], start=1)
            )
            story += [Spacer(1, 0.1 * cm), _p(steps), Spacer(1, 0.3 * cm)]

    return story


def render_pdf(scan: Scan, report_type: str) -> bytes:
    """Documento PDF completo (executivo ou técnico), via reportlab."""
    payload = build_report_payload(scan, report_type)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)

    title = (
        "Relatório Executivo" if report_type == Report.ReportType.EXECUTIVE else "Relatório Técnico"
    )
    story = [
        Paragraph(f"Byakugan — {title}", _STYLES["Title"]),
        Paragraph(
            f"Alvo: {payload['target']} · Gerado em: {payload['generated_at']}", _STYLES["Normal"]
        ),
        Spacer(1, 0.5 * cm),
    ]
    if report_type == Report.ReportType.EXECUTIVE:
        story += _executive_story(payload)
    else:
        story += _technical_story(payload)
    story += [
        Spacer(1, 1 * cm),
        Paragraph(
            "Uso autorizado apenas — protótipo acadêmico (Byakugan, TCC FIAP).", _FOOTER_STYLE
        ),
    ]

    doc.build(story)
    return buffer.getvalue()


RENDERERS = {
    Report.Format.JSON: render_json,
    Report.Format.CSV: render_csv,
    Report.Format.PDF: render_pdf,
}


def render_report(scan: Scan, report_type: str, format: str) -> bytes:
    """Renderiza o relatório no formato solicitado — dispatcher único do serviço."""
    return RENDERERS[format](scan, report_type)
