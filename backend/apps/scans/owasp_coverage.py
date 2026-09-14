"""Matriz de cobertura OWASP Top 10 por scan (2021 + 2025).

Responde objetivamente, para cada uma das 10 categorias de cada edição, três
perguntas do ponto de vista da apresentação/pentest:

- **Testado?** — algum detector que roda neste scan exercita a categoria
  (derivado de ``owasp.ADAPTER_TESTED_CLASSES``, independente de ter achado
  algo). Categorias sem detecção remota confiável (Insecure Design, Logging,
  Mishandling) são marcadas como *cobertura limitada* em vez de fingir teste.
- **Encontrado?** — quantos findings caíram na categoria e a maior severidade.
- **Provado?** — o motor de exploração comprovou impacto para a categoria.

Módulo puro (sem I/O), no mesmo estilo de ``correlation.py``: recebe linhas de
findings (``Finding.objects.values(...)``) e a lista de adapters executados; a
view resolve o banco (triagem/evidências) e apenas repassa os conjuntos.
"""

from __future__ import annotations

from typing import Any

from .owasp import (
    LIMITED_COVERAGE,
    OWASP_2021,
    OWASP_2025,
    adapter_coverage,
    resolve_owasp,
)

#: Ordem de severidade (mais grave primeiro) para calcular a maior severidade.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}


def _highest_severity(severities: list[str]) -> str | None:
    """Maior severidade de uma lista (``None`` se vazia)."""
    present = [s for s in severities if s in _SEVERITY_RANK]
    if not present:
        return None
    return min(present, key=lambda s: _SEVERITY_RANK[s])


def _tested_codes(adapters_run: list[str]) -> tuple[set[str], set[str]]:
    """União dos códigos OWASP (2021, 2025) cobertos pelos adapters executados."""
    codes_2021: set[str] = set()
    codes_2025: set[str] = set()
    for name in adapters_run:
        c21, c25 = adapter_coverage(name)
        codes_2021 |= c21
        codes_2025 |= c25
    return codes_2021, codes_2025


def _edition_rows(
    *,
    edition: str,
    catalog: dict[str, str],
    field: str,
    tested_codes: set[str],
    proven_codes: set[str],
    finding_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Monta as 10 linhas da matriz de uma edição."""
    by_code_sev: dict[str, list[str]] = {code: [] for code in catalog}
    for row in finding_rows:
        code = row.get(field)
        if code in by_code_sev:
            by_code_sev[code].append(row.get("severity", "info"))

    rows: list[dict[str, Any]] = []
    for code, label in catalog.items():
        severities = by_code_sev[code]
        limited = (edition, code) in LIMITED_COVERAGE
        rows.append(
            {
                "code": code,
                "label": label,
                "tested": code in tested_codes,
                "limited_coverage": limited,
                "findings": len(severities),
                "highest_severity": _highest_severity(severities),
                "proven": code in proven_codes,
            }
        )
    return rows


def compute_owasp_coverage(
    *,
    finding_rows: list[dict[str, Any]],
    adapters_run: list[str],
    proven_playbook_keys: set[str] | None = None,
    excluded_dedup_keys: set[str] | None = None,
) -> dict[str, Any]:
    """Calcula a matriz de cobertura OWASP das duas edições para um scan.

    ``finding_rows``: dicts com ``owasp_2021``/``owasp_2025``/``severity``/
    ``dedup_key`` (tipicamente ``scan.findings.values(...)``).
    ``adapters_run``: nomes dos adapters efetivamente executados no scan.
    ``proven_playbook_keys``: ``playbook_key`` com ``Evidence`` provada.
    ``excluded_dedup_keys``: achados triados como resolvidos, excluídos da
    contagem (mesma semântica de ``correlation.compute_risk``).
    """
    excluded = excluded_dedup_keys or set()
    rows = [r for r in finding_rows if r.get("dedup_key") not in excluded]

    tested_2021, tested_2025 = _tested_codes(adapters_run)

    proven_2021: set[str] = set()
    proven_2025: set[str] = set()
    for pk in proven_playbook_keys or set():
        o21, o25, _ = resolve_owasp(playbook_key=pk)
        if o21:
            proven_2021.add(o21)
        if o25:
            proven_2025.add(o25)

    coverage = {
        "2021": _edition_rows(
            edition="2021",
            catalog=OWASP_2021,
            field="owasp_2021",
            tested_codes=tested_2021,
            proven_codes=proven_2021,
            finding_rows=rows,
        ),
        "2025": _edition_rows(
            edition="2025",
            catalog=OWASP_2025,
            field="owasp_2025",
            tested_codes=tested_2025,
            proven_codes=proven_2025,
            finding_rows=rows,
        ),
    }

    for edition_rows in coverage.values():
        for entry in edition_rows:
            entry["status"] = _cell_status(entry)

    coverage["summary"] = {
        edition: _edition_summary(edition_rows) for edition, edition_rows in coverage.items()
    }
    return coverage


def _cell_status(entry: dict[str, Any]) -> str:
    """Rótulo de status de uma célula: found/proven/tested/limited/not-tested."""
    if entry["findings"] > 0:
        return "proven" if entry["proven"] else "found"
    if entry["limited_coverage"]:
        return "limited"
    return "tested" if entry["tested"] else "not-tested"


def _edition_summary(edition_rows: list[dict[str, Any]]) -> dict[str, int]:
    """Contagens agregadas de uma edição para os KPIs da matriz."""
    return {
        "tested": sum(1 for r in edition_rows if r["tested"]),
        "found": sum(1 for r in edition_rows if r["findings"] > 0),
        "proven": sum(1 for r in edition_rows if r["proven"]),
        "limited": sum(1 for r in edition_rows if r["limited_coverage"]),
        "total": len(edition_rows),
    }
