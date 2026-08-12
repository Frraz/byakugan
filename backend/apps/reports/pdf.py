"""Geração do PDF profissional dos relatórios (Fase 5 — redesign UI/UX).

Layout com capa (identidade Byakugan), cabeçalho/rodapé com numeração de
páginas, sumário executivo narrativo, gráficos (donut de severidade e barras
por categoria via ``reportlab.graphics``), tabelas estilizadas com a paleta de
``docs/ui.md`` e seção de referências (CVE/NVD).

O documento impresso usa fundo claro (legibilidade e impressão), com a
identidade visual — navy ``#0B1220`` e electric blue ``#00D4FF`` — aplicada em
faixas, títulos e cabeçalhos de tabela.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from apps.scans.models import Scan

from .models import Report
from .payload import build_report_payload

ASSETS_DIR = Path(__file__).resolve().parent / "assets"
LOGO_PATH = ASSETS_DIR / "logo.png"

# Identidade Byakugan (docs/ui.md).
NAVY = colors.HexColor("#0B1220")
SURFACE = colors.HexColor("#111A2E")
ELECTRIC = colors.HexColor("#00D4FF")
LAVENDER = colors.HexColor("#C8B6FF")
INK = colors.HexColor("#1E293B")
MUTED = colors.HexColor("#64748B")
ZEBRA = colors.HexColor("#F1F5F9")
LINE = colors.HexColor("#E2E8F0")

SEVERITY_COLORS: dict[str, colors.Color] = {
    "critical": colors.HexColor("#EF4444"),
    "high": colors.HexColor("#F97316"),
    "medium": colors.HexColor("#F59E0B"),
    "low": colors.HexColor("#00D4FF"),
    "info": colors.HexColor("#64748B"),
}
SEVERITY_LABELS_PT = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Info",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_BASE = getSampleStyleSheet()
STYLES = {
    "h1": ParagraphStyle("h1", parent=_BASE["Heading1"], textColor=NAVY, fontSize=16, spaceAfter=8),
    "h2": ParagraphStyle(
        "h2", parent=_BASE["Heading2"], textColor=NAVY, fontSize=12, spaceBefore=14, spaceAfter=6
    ),
    "h3": ParagraphStyle("h3", parent=_BASE["Heading3"], textColor=INK, fontSize=10, spaceAfter=4),
    "body": ParagraphStyle("body", parent=_BASE["BodyText"], textColor=INK, fontSize=9, leading=13),
    "small": ParagraphStyle(
        "small", parent=_BASE["BodyText"], textColor=INK, fontSize=8, leading=10
    ),
    "muted": ParagraphStyle("muted", parent=_BASE["Normal"], textColor=MUTED, fontSize=8),
    "cover_title": ParagraphStyle(
        "cover_title", parent=_BASE["Title"], textColor=colors.white, fontSize=30, leading=34
    ),
    "cover_sub": ParagraphStyle(
        "cover_sub", parent=_BASE["Normal"], textColor=ELECTRIC, fontSize=12, alignment=TA_CENTER
    ),
    "cover_meta": ParagraphStyle(
        "cover_meta", parent=_BASE["Normal"], textColor=colors.white, fontSize=11, leading=18
    ),
}


class NumberedCanvas:
    """Fábrica de canvas que injeta "Página X de Y" no rodapé.

    Implementado via subclasse dinâmica de ``canvas.Canvas`` — coleta o estado
    de cada página e escreve o total no ``save`` final (padrão consagrado do
    reportlab para numeração com total de páginas).
    """

    def __new__(cls, *args, **kwargs):  # noqa: D401 — fábrica de canvas
        from reportlab.pdfgen import canvas

        class _Canvas(canvas.Canvas):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                self._saved_states: list[dict] = []

            def showPage(self):
                self._saved_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                total = len(self._saved_states)
                for state in self._saved_states:
                    self.__dict__.update(state)
                    self._draw_footer(total)
                    super().showPage()
                super().save()

            def _draw_footer(self, total: int):
                self.setFont("Helvetica", 7)
                self.setFillColor(MUTED)
                self.drawString(
                    2 * cm,
                    1 * cm,
                    "Uso autorizado apenas — Byakugan · TCC FIAP",
                )
                self.drawRightString(
                    A4[0] - 2 * cm, 1 * cm, f"Página {self._pageNumber} de {total}"
                )
                self.setStrokeColor(LINE)
                self.setLineWidth(0.5)
                self.line(2 * cm, 1.3 * cm, A4[0] - 2 * cm, 1.3 * cm)

        return _Canvas(*args, **kwargs)


def _severity_donut(severity: dict[str, int]) -> Drawing | None:
    """Donut (Pie com furo) da distribuição de findings por severidade."""
    data = [(s, severity.get(s, 0)) for s in SEVERITY_ORDER if severity.get(s, 0) > 0]
    if not data:
        return None

    drawing = Drawing(240, 150)
    pie = Pie()
    pie.x, pie.y = 20, 15
    pie.width = pie.height = 120
    pie.data = [v for _, v in data]
    pie.innerRadiusFraction = 0.55
    pie.slices.strokeColor = colors.white
    pie.slices.strokeWidth = 1.5
    for i, (sev, _) in enumerate(data):
        pie.slices[i].fillColor = SEVERITY_COLORS[sev]
    drawing.add(pie)

    legend = Legend()
    legend.x, legend.y = 155, 120
    legend.fontName = "Helvetica"
    legend.fontSize = 8
    legend.dxTextSpace = 5
    legend.deltay = 12
    legend.colorNamePairs = [
        (SEVERITY_COLORS[sev], f"{SEVERITY_LABELS_PT[sev]}: {v}") for sev, v in data
    ]
    drawing.add(legend)
    return drawing


def _category_bars(heatmap: list[dict[str, Any]]) -> Drawing | None:
    """Barras de findings por categoria (soma das severidades)."""
    totals: dict[str, int] = {}
    for cell in heatmap:
        totals[cell["category"]] = totals.get(cell["category"], 0) + cell["count"]
    totals = {k: v for k, v in totals.items() if v > 0}
    if not totals:
        return None

    items = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:8]
    drawing = Drawing(440, 170)
    chart = VerticalBarChart()
    chart.x, chart.y = 30, 30
    chart.width, chart.height = 380, 120
    chart.data = [[v for _, v in items]]
    chart.categoryAxis.categoryNames = [k for k, _ in items]
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.angle = 20
    chart.categoryAxis.labels.dy = -4
    chart.valueAxis.valueMin = 0
    chart.valueAxis.labels.fontSize = 7
    chart.bars[0].fillColor = ELECTRIC
    chart.barWidth = 10
    drawing.add(chart)
    drawing.add(String(30, 158, "Findings por categoria", fontSize=9, fillColor=INK))
    return drawing


def _styled_table(
    rows: list[list],
    col_widths: list[float],
    *,
    severity_col: int | None = None,
    severities: list[str] | None = None,
) -> Table:
    """Tabela com cabeçalho navy, zebra e (opcional) coluna de severidade colorida."""
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ZEBRA]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK),
    ]
    if severity_col is not None and severities:
        for i, sev in enumerate(severities, start=1):
            color = SEVERITY_COLORS.get(sev)
            if color:
                style.append(("TEXTCOLOR", (severity_col, i), (severity_col, i), color))
                style.append(("FONTNAME", (severity_col, i), (severity_col, i), "Helvetica-Bold"))
    table.setStyle(TableStyle(style))
    return table


def _summary_cards(summary: dict[str, Any]) -> Table:
    """Faixa de KPIs (ativos, risk score, críticas, altas) no topo do relatório."""
    severity = summary["severity"]
    cards = [
        ("Ativos", str(summary["assets"]), NAVY),
        ("Risk Score", f"{summary['risk_score']}/100", ELECTRIC),
        ("Críticas", str(severity["critical"]), SEVERITY_COLORS["critical"]),
        ("Altas", str(severity["high"]), SEVERITY_COLORS["high"]),
    ]
    # Layout horizontal: uma linha, quatro colunas. Leading 22 no valor (18pt)
    # evita que o número grande sobreponha o rótulo abaixo.
    value_style = ParagraphStyle("kpi", parent=STYLES["body"], fontSize=18, leading=22)
    row = [
        [
            Paragraph(f'<font color="{color.hexval()}"><b>{value}</b></font>', value_style),
            Spacer(1, 2),
            Paragraph(label.upper(), STYLES["muted"]),
        ]
        for label, value, color in cards
    ]
    table = Table([row], colWidths=[4 * cm] * 4)
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return table


def _executive_story(payload: dict[str, Any]) -> list:
    story: list = [Paragraph("Sumário executivo", STYLES["h2"])]
    story.append(Paragraph(payload.get("narrative", ""), STYLES["body"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(_summary_cards(payload["summary"]))
    story.append(Spacer(1, 0.5 * cm))

    donut = _severity_donut(payload["summary"]["severity"])
    if donut is not None:
        story.append(Paragraph("Distribuição por severidade", STYLES["h2"]))
        story.append(donut)

    bars = _category_bars(payload.get("heatmap", []))
    if bars is not None:
        story.append(bars)

    story.append(Paragraph("Top riscos priorizados", STYLES["h2"]))
    rows = [["Ativo", "Risk Score", "Nível", "Findings"]]
    for asset in payload["top_risks"]:
        label = asset["hostname"] or asset["ip"] or asset["domain"] or asset["asset"]
        rows.append(
            [label, f"{asset['risk_score']}/100", asset["risk_level"], str(asset["findings"])]
        )
    if len(rows) == 1:
        rows.append(["—", "—", "—", "—"])
    story.append(_styled_table(rows, [7 * cm, 3 * cm, 3 * cm, 3 * cm]))
    return story


def _technical_story(payload: dict[str, Any]) -> list:
    story: list = [Paragraph("Resumo", STYLES["h2"]), _summary_cards(payload["summary"])]
    story.append(Spacer(1, 0.5 * cm))

    meta = payload["scan"]
    story.append(Paragraph("Metadados do scan", STYLES["h2"]))
    meta_rows = [
        ["Tipo", meta["scan_type"]],
        ["Status", meta["status"]],
        ["Autorizado por", meta["authorized_by"]],
        ["Escopo", meta["authorization_scope"]],
        ["Iniciado em", meta["started_at"] or "—"],
        ["Finalizado em", meta["finished_at"] or "—"],
    ]
    meta_table = Table(meta_rows, colWidths=[4 * cm, 12 * cm])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), SURFACE),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("TEXTCOLOR", (1, 0), (1, -1), INK),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story += [meta_table, Spacer(1, 0.4 * cm)]

    story.append(Paragraph("Inventário de ativos", STYLES["h2"]))
    asset_rows = [["Ativo", "SO", "Serviços"]]
    for asset in payload["assets"]:
        asset_rows.append(
            [
                Paragraph(asset["asset"], STYLES["small"]),
                Paragraph(asset["os"] or "—", STYLES["small"]),
                Paragraph(", ".join(asset["services"]) or "—", STYLES["small"]),
            ]
        )
    if len(asset_rows) == 1:
        asset_rows.append(["—", "—", "—"])
    story += [_styled_table(asset_rows, [5 * cm, 3 * cm, 8 * cm]), Spacer(1, 0.4 * cm)]

    story.append(Paragraph("Findings", STYLES["h2"]))
    findings = payload["findings"]
    finding_rows = [["Ativo", "Título", "Sev.", "CVSS", "Evidência", "Recomendação"]]
    for f in findings:
        finding_rows.append(
            [
                Paragraph(f["asset"], STYLES["small"]),
                Paragraph(f["title"], STYLES["small"]),
                Paragraph(SEVERITY_LABELS_PT.get(f["severity"], f["severity"]), STYLES["small"]),
                str(f["cvss"]) if f["cvss"] is not None else "—",
                Paragraph(f["evidence"] or "—", STYLES["small"]),
                Paragraph(f["recommendation"] or "—", STYLES["small"]),
            ]
        )
    if len(finding_rows) == 1:
        finding_rows.append(["—", "—", "—", "—", "—", "—"])
    story.append(
        _styled_table(
            finding_rows,
            [2.6 * cm, 3.2 * cm, 1.6 * cm, 1.3 * cm, 3.6 * cm, 3.7 * cm],
            severity_col=2,
            severities=[f["severity"] for f in findings],
        )
    )

    references = payload.get("references", [])
    if references:
        story += [Spacer(1, 0.5 * cm), Paragraph("Referências", STYLES["h2"])]
        for ref in references:
            title = f'<b>{ref["cve"]}</b> — {ref["title"]}' if ref["cve"] else ref["title"]
            story.append(Paragraph(title, STYLES["body"]))
            for link in ref["links"]:
                story.append(Paragraph(f'<font color="#0369A1">{link}</font>', STYLES["small"]))
            story.append(Spacer(1, 0.2 * cm))

    articles = payload.get("knowledge_articles", [])
    if articles:
        story += [
            Spacer(1, 0.3 * cm),
            Paragraph("Conhecimento relacionado (remediação)", STYLES["h2"]),
        ]
        for article in articles:
            story.append(Paragraph(article["title"], STYLES["h3"]))
            story.append(Paragraph(article["summary"], STYLES["small"]))
            steps = "<br/>".join(
                f"{i}. {step}" for i, step in enumerate(article["remediation_steps"], start=1)
            )
            story += [Paragraph(steps, STYLES["small"]), Spacer(1, 0.3 * cm)]

    return story


def _cover(payload: dict[str, Any], title: str) -> list:
    """Página de capa: faixa navy com logo, título, alvo e data."""
    logo = (
        Image(str(LOGO_PATH), width=6 * cm, height=6 * cm * 768 / 1408)
        if LOGO_PATH.exists()
        else Spacer(1, 2 * cm)
    )
    inner = [
        logo,
        Spacer(1, 1 * cm),
        Paragraph("BYAKUGAN", STYLES["cover_title"]),
        Paragraph("See Everything. Detect Everything.", STYLES["cover_sub"]),
        Spacer(1, 1.5 * cm),
        Paragraph(f'<font color="white" size=16><b>{title}</b></font>', STYLES["cover_meta"]),
        Spacer(1, 0.6 * cm),
        Paragraph(f'Alvo: <b>{payload["target"]}</b>', STYLES["cover_meta"]),
        Paragraph(
            f'Gerado em: {payload["generated_at"][:19].replace("T", " ")}', STYLES["cover_meta"]
        ),
    ]
    banner = Table([[inner]], colWidths=[17 * cm], rowHeights=[23 * cm])
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), NAVY),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("LINEABOVE", (0, 0), (-1, 0), 4, ELECTRIC),
                ("LINEBELOW", (0, -1), (-1, -1), 4, LAVENDER),
            ]
        )
    )
    return [banner, NextPageTemplate("content"), PageBreak()]


def _draw_header(canvas, doc):  # noqa: ANN001 — callback do reportlab
    """Cabeçalho das páginas de conteúdo: logo pequeno + faixa."""
    canvas.saveState()
    if LOGO_PATH.exists():
        canvas.drawImage(
            str(LOGO_PATH),
            2 * cm,
            A4[1] - 2 * cm,
            width=1.2 * cm,
            height=1.2 * cm * 768 / 1408,
            mask="auto",
        )
    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(NAVY)
    canvas.drawString(3.4 * cm, A4[1] - 1.6 * cm, "BYAKUGAN")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1.6 * cm, doc._report_target)
    canvas.setStrokeColor(ELECTRIC)
    canvas.setLineWidth(1)
    canvas.line(2 * cm, A4[1] - 1.9 * cm, A4[0] - 2 * cm, A4[1] - 1.9 * cm)
    canvas.restoreState()


def render_pdf(scan: Scan, report_type: str) -> bytes:
    """Documento PDF completo (executivo ou técnico) com capa e gráficos."""
    payload = build_report_payload(scan, report_type)
    title = (
        "Relatório Executivo" if report_type == Report.ReportType.EXECUTIVE else "Relatório Técnico"
    )

    buffer = io.BytesIO()
    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2.2 * cm,
        bottomMargin=1.6 * cm,
        title=f"Byakugan — {title}",
    )
    doc._report_target = payload["target"]

    cover_frame = Frame(
        0, 0, A4[0], A4[1], id="cover", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0
    )
    content_frame = Frame(2 * cm, 1.5 * cm, A4[0] - 4 * cm, A4[1] - 3.9 * cm, id="content")
    doc.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[cover_frame]),
            PageTemplate(id="content", frames=[content_frame], onPage=_draw_header),
        ]
    )

    story = _cover(payload, title)
    if report_type == Report.ReportType.EXECUTIVE:
        story += _executive_story(payload)
    else:
        story += _technical_story(payload)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
