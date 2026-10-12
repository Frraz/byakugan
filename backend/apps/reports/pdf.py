"""Geração do PDF profissional dos relatórios (PLANO_REDESIGN_BYAKUGAN.md §6).

Layout com capa (identidade Byakugan), cabeçalho/rodapé com numeração de
páginas, sumário executivo narrativo, gráficos (donut de severidade e barras
por categoria via ``reportlab.graphics``), tabelas estilizadas e seção de
referências (CVE/NVD).

O documento impresso usa fundo claro (legibilidade e impressão) — uma
composição editorial distinta do tema escuro da aplicação, mas com a mesma
identidade "Forensic Instrument": acento em latão mineral, sem o navy/electric
blue da identidade "Cyber Navy" anterior. A marca (dois arcos assimétricos +
ponto focal) é desenhada como vetor nativo do reportlab, não como imagem
raster — mesma lógica do símbolo SVG do frontend (`components/brand/Logo.tsx`),
sem depender de um arquivo de imagem.
"""

from __future__ import annotations

import io
import math
from html import escape
from pathlib import Path
from typing import Any

import reportlab
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
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


def _arc_start(cx: float, cy: float, r: float, start_deg: float) -> tuple[float, float]:
    a = math.radians(start_deg)
    return cx + r * math.cos(a), cy + r * math.sin(a)


def _stroke_arc(
    c,
    cx: float,
    cy: float,
    r: float,
    start_deg: float,
    extent_deg: float,
    color: colors.Color,
    width: float,
    alpha: float = 1.0,
) -> None:
    """Desenha um arco aberto (só o traço) via ``arcTo`` — ``canvas.arc`` sozinho
    não existe no pdfgen; path precisa iniciar com ``moveTo`` no ponto de
    partida exato do arco para não criar um segmento reto espúrio."""
    sx, sy = _arc_start(cx, cy, r, start_deg)
    c.saveState()
    c.setStrokeColor(color)
    c.setStrokeAlpha(alpha)
    c.setLineCap(1)  # round
    c.setLineWidth(width)
    p = c.beginPath()
    p.moveTo(sx, sy)
    p.arcTo(cx - r, cy - r, cx + r, cy + r, startAng=start_deg, extent=extent_deg)
    c.drawPath(p, stroke=1, fill=0)
    c.restoreState()


def _draw_mark(c, cx: float, cy: float, size: float, color: colors.Color) -> None:
    """Marca Byakugan: dois arcos assimétricos + ponto focal (vetor nativo).

    Mesma linguagem visual do símbolo SVG do frontend — não um olho literal,
    lê-se como um instrumento de foco/precisão. Funciona em qualquer tamanho
    e cor de traço; ``size`` em pontos (unidade do reportlab).
    """
    width = max(size * 0.075, 1)
    r1 = size * 0.44
    _stroke_arc(c, cx, cy - size * 0.06, r1, 24, 132, color, width)
    r2 = size * 0.28
    _stroke_arc(
        c, cx + size * 0.02, cy - size * 0.30, r2, 28, 124, color, width, alpha=0.55
    )
    c.saveState()
    c.setFillColor(color)
    c.circle(cx - size * 0.09, cy - size * 0.02, size * 0.075, stroke=0, fill=1)
    c.restoreState()


class _MarkFlowable(Flowable):
    """Envolve ``_draw_mark`` como flowable Platypus (uso na capa)."""

    def __init__(self, size: float, color: colors.Color):
        super().__init__()
        self.width = self.height = size
        self._size = size
        self._color = color

    def draw(self) -> None:
        _draw_mark(self.canv, self.width / 2, self.height / 2, self._size, self._color)


# Identidade "Forensic Instrument" (PLANO_REDESIGN_BYAKUGAN.md §3, §6) — a
# mesma identidade do frontend, adaptada a uma publicação editorial clara
# (fundo branco), não ao tema escuro da aplicação. INK quase-preto substitui
# o navy antigo; BRASS (o acento de marca, escurecido para contraste em
# fundo claro) substitui o electric blue/lavender da identidade "Cyber Navy"
# anterior.
INK_DARK = colors.HexColor("#15171B")  # faixa da capa, cabeçalho de tabela
BRASS = colors.HexColor("#8C6A32")  # acento de marca (texto/traço em fundo claro)
BRASS_LIGHT = colors.HexColor("#D4AE73")  # acento de marca em fundo escuro (capa)
INK = colors.HexColor("#1E232B")
MUTED = colors.HexColor("#6B7280")
ZEBRA = colors.HexColor("#F3F2EE")
LINE = colors.HexColor("#E2E0DB")

SEVERITY_COLORS: dict[str, colors.Color] = {
    "critical": colors.HexColor("#C9404B"),
    "high": colors.HexColor("#95501F"),
    "medium": colors.HexColor("#8A6D16"),
    "low": colors.HexColor("#2E6E8C"),
    "info": colors.HexColor("#5B6472"),
}
SEVERITY_LABELS_PT = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Info",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
#: Rótulos PT-BR do impacto *comprovado* (``Evidence.impact_level``) — espelha
#: ``frontend/src/components/evidence/ImpactBadge.tsx:IMPACT_LABELS``.
IMPACT_LABELS_PT = {
    "rce": "Execução remota de código",
    "db-read": "Leitura de banco de dados",
    "file-read": "Leitura de arquivos",
    "auth-bypass": "Bypass de autenticação",
    "ssrf": "Acesso interno (SSRF)",
    "info-disclosure": "Vazamento de informação",
    "session": "Roubo de sessão",
    "none": "Sem impacto",
}

# Fontes distribuídas pelo ReportLab: embutidas no PDF, sem depender do host.
_FONT_DIR = Path(reportlab.__file__).parent / "fonts"
for _name, _file in (
    ("ByakuganSans", "Vera.ttf"),
    ("ByakuganSans-Bold", "VeraBd.ttf"),
    ("ByakuganSans-Italic", "VeraIt.ttf"),
    ("ByakuganSans-BoldItalic", "VeraBI.ttf"),
):
    pdfmetrics.registerFont(TTFont(_name, str(_FONT_DIR / _file)))
pdfmetrics.registerFontFamily(
    "ByakuganSans",
    normal="ByakuganSans",
    bold="ByakuganSans-Bold",
    italic="ByakuganSans-Italic",
    boldItalic="ByakuganSans-BoldItalic",
)


def _text(value: Any) -> str:
    """Escapa dados externos para o parser de markup; preserva linhas de evidência."""
    return escape(str(value or "—")).replace("\n", "<br/>")


_BASE = getSampleStyleSheet()
for _style in _BASE.byName.values():
    _style.fontName = (
        "ByakuganSans-Bold" if "Heading" in _style.name else "ByakuganSans"
    )
    _style.splitLongWords = True
STYLES = {
    "h1": ParagraphStyle(
        "h1", parent=_BASE["Heading1"], textColor=INK_DARK, fontSize=16, spaceAfter=8
    ),
    "h2": ParagraphStyle(
        "h2",
        parent=_BASE["Heading2"],
        textColor=INK_DARK,
        fontSize=12,
        spaceBefore=14,
        spaceAfter=6,
    ),
    "h3": ParagraphStyle(
        "h3", parent=_BASE["Heading3"], textColor=INK, fontSize=10, spaceAfter=4
    ),
    "body": ParagraphStyle(
        "body", parent=_BASE["BodyText"], textColor=INK, fontSize=9, leading=13
    ),
    "small": ParagraphStyle(
        "small", parent=_BASE["BodyText"], textColor=INK, fontSize=8, leading=10
    ),
    "muted": ParagraphStyle(
        "muted", parent=_BASE["Normal"], textColor=MUTED, fontSize=8
    ),
    "cover_title": ParagraphStyle(
        "cover_title",
        parent=_BASE["Title"],
        textColor=colors.white,
        fontSize=30,
        leading=34,
    ),
    "cover_sub": ParagraphStyle(
        "cover_sub",
        parent=_BASE["Normal"],
        textColor=BRASS_LIGHT,
        fontSize=12,
        alignment=TA_CENTER,
    ),
    "cover_meta": ParagraphStyle(
        "cover_meta",
        parent=_BASE["Normal"],
        textColor=colors.white,
        fontSize=11,
        leading=18,
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
                self.setFont("ByakuganSans", 7)
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
    legend.fontName = "ByakuganSans"
    legend.fontSize = 8
    legend.dxTextSpace = 5
    legend.deltay = 12
    legend.colorNamePairs = [
        (SEVERITY_COLORS[sev], f"{SEVERITY_LABELS_PT[sev]}: {v}") for sev, v in data
    ]
    drawing.add(legend)
    return drawing


def _category_bars(heatmap: list[dict[str, Any]]) -> Drawing | None:
    """Barras horizontais legíveis, com valores e rótulos de categoria."""
    from reportlab.graphics.shapes import Rect

    totals: dict[str, int] = {}
    for cell in heatmap:
        label = cell.get("category_label") or cell["category"]
        totals[label] = totals.get(label, 0) + cell["count"]
    items = sorted(
        ((key, value) for key, value in totals.items() if value > 0),
        key=lambda item: item[1],
        reverse=True,
    )[:8]
    if not items:
        return None
    height = 30 + 26 * len(items)
    drawing = Drawing(440, height)
    maximum = max(value for _, value in items)
    drawing.add(
        String(
            0,
            height - 12,
            "Findings por categoria",
            fontName="ByakuganSans-Bold",
            fontSize=9,
            fillColor=INK,
        )
    )
    for index, (label, value) in enumerate(items):
        y = height - 38 - index * 26
        drawing.add(
            String(0, y + 10, label, fontName="ByakuganSans", fontSize=8, fillColor=INK)
        )
        width = 400 * value / maximum
        drawing.add(Rect(0, y - 2, width, 5, fillColor=BRASS, strokeColor=None))
        drawing.add(
            String(
                410,
                y - 2,
                str(value),
                fontName="ByakuganSans",
                fontSize=8,
                fillColor=INK,
            )
        )
    return drawing


def _styled_table(
    rows: list[list],
    col_widths: list[float],
    *,
    severity_col: int | None = None,
    severities: list[str] | None = None,
) -> Table:
    """Tabela com cabeçalho escuro, zebra e (opcional) coluna de severidade colorida."""
    wrapped = []
    for index, row in enumerate(rows):
        cells = []
        for column, cell in enumerate(row):
            if isinstance(cell, str):
                color = colors.white if index == 0 else INK
                if (
                    index
                    and severity_col == column
                    and severities
                    and index <= len(severities)
                ):
                    color = SEVERITY_COLORS.get(severities[index - 1], INK)
                style = ParagraphStyle(
                    "table-cell",
                    parent=STYLES["small"],
                    textColor=color,
                    fontName="ByakuganSans-Bold" if index == 0 else "ByakuganSans",
                )
                cell = Paragraph(_text(cell), style)
            cells.append(cell)
        wrapped.append(cells)
    table = Table(wrapped, colWidths=col_widths, repeatRows=1, splitInRow=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), INK_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "ByakuganSans-Bold"),
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
                style.append(
                    (
                        "FONTNAME",
                        (severity_col, i),
                        (severity_col, i),
                        "ByakuganSans-Bold",
                    )
                )
    table.setStyle(TableStyle(style))
    return table


def _summary_cards(summary: dict[str, Any]) -> Table:
    """Faixa de KPIs (ativos, risk score, críticas, altas) no topo do relatório."""
    severity = summary["severity"]
    cards = [
        ("Ativos", str(summary["assets"]), INK_DARK),
        ("Risk Score", f"{summary['risk_score']}/100", BRASS),
        ("Críticas", str(severity["critical"]), SEVERITY_COLORS["critical"]),
        ("Altas", str(severity["high"]), SEVERITY_COLORS["high"]),
    ]
    # Layout horizontal: uma linha, quatro colunas. Leading 22 no valor (18pt)
    # evita que o número grande sobreponha o rótulo abaixo.
    value_style = ParagraphStyle("kpi", parent=STYLES["body"], fontSize=18, leading=22)
    row = [
        [
            Paragraph(
                f'<font color="{color.hexval()}"><b>{value}</b></font>', value_style
            ),
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


_OWASP_STATUS_PT = {
    "proven": "Provado",
    "found": "Encontrado",
    "tested": "Testado",
    "limited": "Cobertura limitada",
    "not-tested": "Não testado",
}
_OWASP_STATUS_COLOR = {
    "proven": SEVERITY_COLORS["critical"],
    "found": SEVERITY_COLORS["high"],
    "tested": colors.HexColor("#226B4D"),
    "limited": MUTED,
    "not-tested": MUTED,
}


def _owasp_edition_table(edition_rows: list[dict[str, Any]]) -> Table:
    """Tabela A01–A10 de uma edição OWASP: categoria, status, findings, severidade."""
    rows = [["OWASP", "Categoria", "Situação", "Findings", "Maior sev."]]
    statuses: list[str] = []
    for entry in edition_rows:
        # O rótulo já vem como "A01:2021 - Broken Access Control"; separa código
        # e nome para caber na tabela.
        label = entry["label"]
        code, _, name = label.partition(" - ")
        sev = entry["highest_severity"]
        rows.append(
            [
                code,
                Paragraph(_text(name or label), STYLES["small"]),
                _OWASP_STATUS_PT.get(entry["status"], entry["status"]),
                str(entry["findings"]),
                SEVERITY_LABELS_PT.get(sev, "—") if sev else "—",
            ]
        )
        statuses.append(entry["status"])
    table = _styled_table(rows, [2.6 * cm, 6.4 * cm, 3.4 * cm, 1.8 * cm, 1.8 * cm])
    # Colore a coluna "Situação" pelo status.
    style = []
    for i, st in enumerate(statuses, start=1):
        color = _OWASP_STATUS_COLOR.get(st)
        if color:
            style.append(("TEXTCOLOR", (2, i), (2, i), color))
            style.append(("FONTNAME", (2, i), (2, i), "ByakuganSans-Bold"))
    table.setStyle(TableStyle(style))
    return table


def _attack_narrative_section(payload: dict[str, Any]) -> list:
    """Seção 'Narrativa de Ataque' — como um atacante encadearia o que foi *provado*.

    Só existe quando há ao menos um ativo com `Evidence` `proven`
    (``payload.build_attack_narrative``) — ausente num relatório sem
    exploração habilitada/bem-sucedida, nunca uma seção vazia forçada.
    """
    narrative = payload.get("attack_narrative")
    if not narrative:
        return []
    story: list = [
        Paragraph("Narrativa de Ataque", STYLES["h2"]),
        Paragraph(
            "Sequência de impacto comprovado por ativo — o que o Byakugan de fato "
            "demonstrou, não uma especulação sobre findings não explorados.",
            STYLES["muted"],
        ),
        Spacer(1, 0.2 * cm),
    ]
    for entry in narrative:
        story.append(
            Paragraph(
                f'{_text(entry["asset"])} — impacto máximo: '
                f'<b>{IMPACT_LABELS_PT.get(entry["max_impact"], entry["max_impact"])}</b>',
                STYLES["h3"],
            )
        )
        if entry["mitre_techniques"]:
            story.append(
                Paragraph(
                    "Técnicas MITRE ATT&amp;CK: "
                    + ", ".join(entry["mitre_techniques"]),
                    STYLES["small"],
                )
            )
        for i, step in enumerate(entry["steps"], start=1):
            technique = (
                f' [{step["mitre_technique"]} — {step["mitre_technique_name"]}]'
                if step["mitre_technique"]
                else ""
            )
            story.append(
                Paragraph(
                    f'{i}. <b>{_text(step["title"])}</b> — '
                    f'{IMPACT_LABELS_PT.get(step["impact_level"], step["impact_level"])}{technique}',
                    STYLES["small"],
                )
            )
            if step["proof"]:
                story.append(Paragraph(_text(step["proof"]), STYLES["muted"]))
        for chain in entry["chains"]:
            story.append(
                Paragraph(
                    f'Cadeia de risco: <b>{_text(chain["title"])}</b> — {_text(chain["description"])}',
                    STYLES["small"],
                )
            )
        story.append(Spacer(1, 0.3 * cm))
    return story


def _owasp_coverage_section(payload: dict[str, Any]) -> list:
    """Seção 'Cobertura OWASP Top 10' (2021 + 2025) — o entregável central."""
    coverage = payload.get("owasp_coverage")
    if not coverage:
        return []
    story: list = [Paragraph("Cobertura OWASP Top 10", STYLES["h2"])]
    summary = coverage.get("summary", {})
    for edition in ("2021", "2025"):
        rows = coverage.get(edition)
        if not rows:
            continue
        s = summary.get(edition, {})
        story.append(Paragraph(f"Edição {edition}", STYLES["h3"]))
        story.append(
            Paragraph(
                f"Testadas: {s.get('tested', 0)}/{s.get('total', 10)} · "
                f"Com findings: {s.get('found', 0)} · Provadas: {s.get('proven', 0)} · "
                f"Cobertura limitada: {s.get('limited', 0)}.",
                STYLES["muted"],
            )
        )
        story.append(Spacer(1, 0.15 * cm))
        story.append(_owasp_edition_table(rows))
        story.append(Spacer(1, 0.35 * cm))
    return story


def _executive_story(payload: dict[str, Any]) -> list:
    story: list = [Paragraph("Sumário executivo", STYLES["h2"])]
    story.append(Paragraph(_text(payload.get("narrative", "")), STYLES["body"]))
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
            [
                label,
                f"{asset['risk_score']}/100",
                SEVERITY_LABELS_PT.get(asset["risk_level"], asset["risk_level"]),
                str(asset["findings"]),
            ]
        )
    if len(rows) == 1:
        rows.append(["—", "—", "—", "—"])
    story.append(_styled_table(rows, [7 * cm, 3 * cm, 3 * cm, 3 * cm]))

    story.append(Spacer(1, 0.5 * cm))
    story += _owasp_coverage_section(payload)
    return story


def _technical_story(payload: dict[str, Any]) -> list:
    story: list = [
        Paragraph("Resumo", STYLES["h2"]),
        _summary_cards(payload["summary"]),
    ]
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
    meta_rows = [
        [
            Paragraph(
                _text(label),
                ParagraphStyle(
                    "meta-label", parent=STYLES["small"], textColor=colors.white
                ),
            ),
            Paragraph(_text(value), STYLES["small"]),
        ]
        for label, value in meta_rows
    ]
    meta_table = Table(meta_rows, colWidths=[4 * cm, 12 * cm], splitInRow=1)
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), INK_DARK),
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
                Paragraph(_text(asset["asset"]), STYLES["small"]),
                Paragraph(_text(asset["os"] or "—"), STYLES["small"]),
                Paragraph(_text(", ".join(asset["services"]) or "—"), STYLES["small"]),
            ]
        )
    if len(asset_rows) == 1:
        asset_rows.append(["—", "—", "—"])
    story += [_styled_table(asset_rows, [5 * cm, 3 * cm, 8 * cm]), Spacer(1, 0.4 * cm)]

    story.append(Paragraph("Findings", STYLES["h2"]))
    findings = payload["findings"]
    if not findings:
        story.append(
            Paragraph(
                "Nenhum finding registrado neste scan. Isso não comprova ausência de vulnerabilidades.",
                STYLES["body"],
            )
        )
    for index, finding in enumerate(findings, start=1):
        story.append(Paragraph(f"{index}. {_text(finding['title'])}", STYLES["h3"]))
        story.append(Paragraph(f"Ativo: {_text(finding['asset'])}", STYLES["small"]))
        severity = SEVERITY_LABELS_PT.get(finding["severity"], finding["severity"])
        cvss = finding.get("cvss")
        story.append(
            Paragraph(
                f"Severidade: {_text(severity)} · CVSS: {cvss if cvss is not None else '—'}",
                STYLES["small"],
            )
        )
        taxonomy = " · ".join(
            str(finding.get(key))
            for key in ("cve", "cwe", "owasp_2021", "owasp_2025", "mitre_technique")
            if finding.get(key)
        )
        if taxonomy:
            story.append(Paragraph(_text(taxonomy), STYLES["small"]))
        for label, key in (
            ("Descrição", "description"),
            ("Evidência de detecção", "evidence"),
            ("Recomendação", "recommendation"),
        ):
            story.append(Paragraph(f"<b>{label}</b>", STYLES["body"]))
            story.append(Paragraph(_text(finding.get(key)), STYLES["body"]))
        story.append(Spacer(1, 0.4 * cm))

    story.append(Spacer(1, 0.5 * cm))
    story += _attack_narrative_section(payload)

    story.append(Spacer(1, 0.5 * cm))
    story += _owasp_coverage_section(payload)

    references = payload.get("references", [])
    if references:
        story += [Spacer(1, 0.5 * cm), Paragraph("Referências", STYLES["h2"])]
        for ref in references:
            title = (
                f'<b>{_text(ref["cve"])}</b> — {_text(ref["title"])}'
                if ref["cve"]
                else _text(ref["title"])
            )
            story.append(Paragraph(title, STYLES["body"]))
            for link in ref["links"]:
                story.append(
                    Paragraph(
                        f'<font color="{BRASS.hexval()}">{_text(link)}</font>',
                        STYLES["small"],
                    )
                )
            story.append(Spacer(1, 0.2 * cm))

    articles = payload.get("knowledge_articles", [])
    if articles:
        story += [
            Spacer(1, 0.3 * cm),
            Paragraph("Conhecimento relacionado (remediação)", STYLES["h2"]),
        ]
        for article in articles:
            story.append(Paragraph(_text(article["title"]), STYLES["h3"]))
            story.append(Paragraph(_text(article["summary"]), STYLES["small"]))
            steps = "<br/>".join(
                f"{i}. {_text(step)}"
                for i, step in enumerate(article["remediation_steps"], start=1)
            )
            story += [Paragraph(steps, STYLES["small"]), Spacer(1, 0.3 * cm)]

    return story


def _cover(payload: dict[str, Any], title: str) -> list:
    """Página de capa: faixa escura com marca, título, alvo e data.

    Sem grandes efeitos (PLANO_REDESIGN_BYAKUGAN.md §6.1) — uma única linha
    de acento, sem gradientes nem bordas duplas decorativas.
    """
    mark = _MarkFlowable(2.4 * cm, BRASS_LIGHT)
    inner = [
        mark,
        Spacer(1, 1 * cm),
        Paragraph("BYAKUGAN", STYLES["cover_title"]),
        Paragraph("SECURITY ASSESSMENT", STYLES["cover_sub"]),
        Spacer(1, 1.5 * cm),
        Paragraph(
            f'<font color="white" size=16><b>{title}</b></font>', STYLES["cover_meta"]
        ),
        Spacer(1, 0.6 * cm),
        Paragraph(f'Alvo: <b>{_text(payload["target"])}</b>', STYLES["cover_meta"]),
        Paragraph(
            f'Gerado em: {payload["generated_at"][:19].replace("T", " ")} UTC',
            STYLES["cover_meta"],
        ),
    ]
    banner = Table([[inner]], colWidths=[17 * cm], rowHeights=[23 * cm])
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), INK_DARK),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("LINEABOVE", (0, 0), (-1, 0), 3, BRASS_LIGHT),
            ]
        )
    )
    return [banner, NextPageTemplate("content"), PageBreak()]


def _draw_header(canvas, doc):  # noqa: ANN001 — callback do reportlab
    """Cabeçalho das páginas de conteúdo: marca pequena + faixa."""
    canvas.saveState()
    _draw_mark(canvas, 2 * cm + 0.6 * cm, A4[1] - 2 * cm + 0.6 * cm, 1.2 * cm, BRASS)
    canvas.setFont("ByakuganSans-Bold", 10)
    canvas.setFillColor(INK_DARK)
    canvas.drawString(3.4 * cm, A4[1] - 1.6 * cm, "BYAKUGAN")
    canvas.setFont("ByakuganSans", 7)
    canvas.setFillColor(MUTED)
    target = doc._report_target
    # O valor completo aparece na capa; o cabeçalho não invade a marca.
    while pdfmetrics.stringWidth(target, "ByakuganSans", 7) > 9 * cm:
        target = target[:-2]
    if target != doc._report_target:
        target += "…"
    canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1.6 * cm, target)
    canvas.setStrokeColor(BRASS)
    canvas.setLineWidth(1)
    canvas.line(2 * cm, A4[1] - 1.9 * cm, A4[0] - 2 * cm, A4[1] - 1.9 * cm)
    canvas.restoreState()


class _ReportDocTemplate(BaseDocTemplate):
    """Adiciona navegação por seções ao painel de marcadores do leitor PDF."""

    def afterFlowable(self, flowable: Flowable) -> None:
        """Registra títulos reais sem estimar números de página."""
        if not isinstance(flowable, Paragraph) or flowable.style.name not in {
            "h2",
            "h3",
        }:
            return
        index = getattr(self, "_heading_index", 0)
        self._heading_index = index + 1
        key = f"section-{index}"
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(
            flowable.getPlainText(), key, level=0 if flowable.style.name == "h2" else 1
        )


def render_pdf(scan: Scan, report_type: str) -> bytes:
    """Documento PDF completo (executivo ou técnico) com capa e gráficos."""
    payload = build_report_payload(scan, report_type)
    title = (
        "Relatório Executivo"
        if report_type == Report.ReportType.EXECUTIVE
        else "Relatório Técnico"
    )

    buffer = io.BytesIO()
    doc = _ReportDocTemplate(
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
        0,
        0,
        A4[0],
        A4[1],
        id="cover",
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )
    content_frame = Frame(
        2 * cm, 1.5 * cm, A4[0] - 4 * cm, A4[1] - 3.9 * cm, id="content"
    )
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
