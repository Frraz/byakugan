"""Mapeamento de respostas da API NVD (CVE 2.0) para o domínio de findings.

Regras puras (sem I/O): traduzem o payload JSON de uma vulnerabilidade
retornada pela NVD em campos prontos para persistência (``Vulnerability`` /
``Finding``). Isolar essa lógica de ``adapters.py`` (que cuida da coleta em
rede) a torna testável sem mockar requisições HTTP — mesmo padrão adotado em
``signatures.py`` para o fingerprint HTTP.
"""

from __future__ import annotations

from typing import Any

from .models import Severity

# Ordem de preferência das métricas CVSS retornadas pela NVD (mais recente
# primeiro). CVEs mais antigos só possuem v2.
_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def severity_bucket(score: float | None, nvd_label: str | None = None) -> str:
    """Classifica a severidade (RN004) a partir do rótulo da NVD ou do CVSS.

    Prioriza o ``baseSeverity`` informado pela NVD quando disponível; caso
    contrário, deriva a faixa a partir do score CVSS pelos limiares padrão.
    """
    if nvd_label:
        label = nvd_label.lower()
        if label in {"critical", "high", "medium", "low"}:
            return label
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _best_metric(metrics: dict[str, Any]) -> tuple[float | None, str | None, str]:
    """Escolhe a métrica CVSS mais recente disponível (v3.1 > v3.0 > v2)."""
    for key in _METRIC_KEYS:
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("vectorString")
            label = entry.get("baseSeverity") or data.get("baseSeverity")
            return score, vector, severity_bucket(score, label)
    return None, None, Severity.INFO


def map_cve_item(item: dict[str, Any]) -> dict[str, Any] | None:
    """Converte um item do payload NVD (``{"cve": {...}}``) em campos de domínio.

    Retorna ``None`` quando o item não traz um identificador CVE (payload
    inesperado) — o caller deve simplesmente ignorá-lo.
    """
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    description = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    score, vector, severity = _best_metric(cve.get("metrics", {}))
    references = [r["url"] for r in cve.get("references", []) if r.get("url")]

    return {
        "cve": cve_id,
        "description": description,
        "cvss_score": score,
        "cvss_vector": vector,
        "severity": severity,
        "references": references,
    }
