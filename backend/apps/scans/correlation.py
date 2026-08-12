"""Correlation Engine: risk score, priorização e agrupamento (Fase 4).

Regras puras (sem I/O) que transformam findings em *risk assessment* por
ativo e por ambiente. O motor não persiste nada: risco é sempre **computado
sob demanda** a partir dos ``Finding`` já persistidos (RN003 — histórico
imutável), então nunca fica desatualizado e não exige invalidação de cache.
Ver docs/scanning-engine.md (seção Correlation Engine) para o racional.

As funções recebem listas de dicts (tipicamente vindas de
``Finding.objects.values(...)``) para evitar instanciar objetos de modelo
desnecessariamente e para permanecerem testáveis sem banco de dados.

Fase 5 (dedup/triagem): as funções aceitam ``excluded_dedup_keys`` opcional —
um conjunto de ``Finding.dedup_key`` triados como corrigido/falso-positivo/
risco aceito (``FindingTriage``), resolvido pelo caller (``views.py``) e
apenas filtrado aqui. Mantém este módulo livre de I/O: quem consulta o banco
por triagens é a view, não o motor de correlação.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from .models import FindingCategory

# CVSS "equivalente" usado quando o finding não possui CVSS numérico (ex.:
# vulnerabilidades sem CVE associado). Mantém a mesma ordem de grandeza do
# CVSS real para que a soma continue comparável entre findings.
SEVERITY_FALLBACK_SCORE: dict[str, float] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.0,
    "info": 0.0,
}

SEVERITIES = ("critical", "high", "medium", "low", "info")

# risk_score satura em 100 — evita que ambientes com muitos findings percam
# a diferenciação entre "ruim" e "catastrófico".
RISK_SCORE_CAP = 100.0

#: Rótulo amigável (PT-BR) por categoria de finding — reaproveita os labels
#: já declarados em ``FindingCategory`` (fonte única, sem duplicar em cada
#: consumidor da API/frontend).
CATEGORY_LABELS: dict[str, str] = dict(FindingCategory.choices)


def category_label(category: str) -> str:
    """Rótulo amigável de uma categoria — usado pela UI (heatmap/legendas).

    Categorias fora do enum (ex.: dado legado de antes da Fase 0) caem no
    próprio valor bruto, nunca quebram.
    """
    return CATEGORY_LABELS.get(category, category)


def _exclude_triaged(
    rows: list[dict[str, Any]], excluded_dedup_keys: set[str] | None
) -> list[dict[str, Any]]:
    """Remove de ``rows`` os findings cujo ``dedup_key`` já foi triado como resolvido."""
    if not excluded_dedup_keys:
        return rows
    return [r for r in rows if r.get("dedup_key") not in excluded_dedup_keys]


def risk_level(score: float) -> str:
    """Classifica o ``risk_score`` (0-100) na mesma banda usada para CVSS (×10).

    Os limiares espelham exatamente ``cve.severity_bucket`` escalado por 10
    (CVSS 9.0 → risk 90, 7.0 → 70, 4.0 → 40), mantendo a semântica de
    severidade consistente em toda a plataforma.
    """
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _finding_weight(severity: str, cvss: float | None) -> float:
    """Peso de um finding no risk_score: CVSS real, ou fallback por severidade."""
    if cvss is not None:
        return float(cvss)
    return SEVERITY_FALLBACK_SCORE.get(severity, 0.0)


def _empty_severity_counts() -> dict[str, int]:
    return dict.fromkeys(SEVERITIES, 0)


@dataclass
class RiskAssessment:
    """Risk assessment computado sobre um conjunto de findings."""

    risk_score: float
    risk_level: str
    severity: dict[str, int] = field(default_factory=_empty_severity_counts)
    findings: int = 0


def compute_risk(
    rows: list[dict[str, Any]], *, excluded_dedup_keys: set[str] | None = None
) -> RiskAssessment:
    """Calcula o risk score (0-100) e a distribuição de severidade.

    ``rows``: lista de dicts com ao menos ``severity`` e ``cvss``. O score é
    a soma dos pesos (CVSS real ou fallback), saturada em 100 — ou seja,
    cresce com o número e a gravidade dos findings, mas nunca "explode".

    ``excluded_dedup_keys``, quando informado, remove da soma os findings
    cujo ``dedup_key`` já foi triado como corrigido/falso-positivo/risco
    aceito (Fase 5) — sem isso, reexecutar o mesmo scan sobre o mesmo alvo
    infla o score aditivo a cada rodada, mesmo sem mudança real de risco.
    """
    rows = _exclude_triaged(rows, excluded_dedup_keys)
    counts = Counter(r["severity"] for r in rows)
    raw = sum(_finding_weight(r["severity"], r.get("cvss")) for r in rows)
    score = min(RISK_SCORE_CAP, round(raw, 1))
    severity = _empty_severity_counts()
    severity.update({k: v for k, v in counts.items() if k in severity})
    return RiskAssessment(
        risk_score=score,
        risk_level=risk_level(score),
        severity=severity,
        findings=len(rows),
    )


def compute_asset_risk(
    rows: list[dict[str, Any]], *, excluded_dedup_keys: set[str] | None = None
) -> list[dict[str, Any]]:
    """Agrupa findings por ativo e computa o risk assessment de cada um.

    ``rows`` deve incluir ``asset_id`` (e, opcionalmente, campos de exibição
    do ativo como ``asset__ip``/``asset__hostname``/``asset__domain``, que são
    repassados como ``ip``/``hostname``/``domain``). Retorna ordenado por
    ``risk_score`` decrescente — a priorização automática do Correlation
    Engine. ``excluded_dedup_keys``: ver ``compute_risk``.
    """
    rows = _exclude_triaged(rows, excluded_dedup_keys)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    display: dict[str, dict[str, Any]] = {}
    for row in rows:
        asset_id = str(row["asset_id"])
        groups[asset_id].append(row)
        display.setdefault(
            asset_id,
            {
                "ip": row.get("asset__ip"),
                "hostname": row.get("asset__hostname"),
                "domain": row.get("asset__domain"),
            },
        )

    assessments = [
        {"asset": asset_id, **display[asset_id], **asdict(compute_risk(asset_rows))}
        for asset_id, asset_rows in groups.items()
    ]
    assessments.sort(key=lambda a: a["risk_score"], reverse=True)
    return assessments


def compute_heatmap(
    rows: list[dict[str, Any]], *, excluded_dedup_keys: set[str] | None = None
) -> list[dict[str, Any]]:
    """Agrega a contagem de findings por (categoria, severidade).

    ``rows`` deve incluir ``category`` e ``severity``. Retorna uma lista
    plana de células ``{"category", "category_label", "severity", "count"}``
    — o frontend faz o pivô para a grade do heatmap; ``category_label`` evita
    duplicar o mapa categoria→rótulo em cada consumidor. Findings triados
    como resolvidos (``excluded_dedup_keys`` — ver ``compute_risk``) não
    entram na contagem, mantendo o heatmap consistente com o risk_score.
    """
    rows = _exclude_triaged(rows, excluded_dedup_keys)
    counter: Counter[tuple[str, str]] = Counter()
    for row in rows:
        counter[(row["category"], row["severity"])] += 1
    return [
        {
            "category": category,
            "category_label": category_label(category),
            "severity": severity,
            "count": count,
        }
        for (category, severity), count in sorted(counter.items())
    ]
