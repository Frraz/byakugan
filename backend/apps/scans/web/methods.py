"""Checagem de métodos HTTP perigosos (Fase 4 — category ``http-method``).

Só ``OPTIONS`` e ``TRACE`` são usados ativamente (idempotentes, nunca
alteram estado no servidor) — **nunca** ``PUT``/``DELETE``/``PATCH`` reais,
que poderiam de fato escrever/apagar algo no alvo. A exposição de
``PUT``/``DELETE`` é detectada de forma passiva, apenas lendo o header
``Allow`` devolvido por uma requisição ``OPTIONS``.
"""

from __future__ import annotations

from typing import Any

#: Métodos cuja simples disponibilidade (via Allow) já é significativa.
_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


def _finding(
    *, title: str, severity: str, description: str, evidence: str, recommendation: str
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "category": "http-method",
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def analyze_allow_header(url: str, allow_header: str | None) -> list[dict[str, Any]]:
    """Interpreta o header ``Allow`` de uma resposta ``OPTIONS``."""
    if not allow_header:
        return []

    methods = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
    dangerous = sorted(methods & _DANGEROUS_METHODS)
    if not dangerous:
        return []

    return [
        _finding(
            title=f"Métodos HTTP potencialmente perigosos habilitados: {', '.join(dangerous)}",
            severity="medium",
            description=(
                f"A resposta OPTIONS de '{url}' anuncia os métodos {', '.join(dangerous)} "
                "como permitidos. PUT/DELETE podem permitir escrita/remoção de recursos "
                "se não houver autorização adequada; TRACE/CONNECT habilitam ataques de "
                "Cross-Site Tracing (XST) e podem vazar headers sensíveis."
            ),
            evidence=f"OPTIONS {url} → Allow: {allow_header}",
            recommendation=(
                "Desabilitar métodos não utilizados no servidor/roteador (mínimo "
                "privilégio) e exigir autenticação/autorização para PUT/DELETE quando necessários."
            ),
        )
    ]


def analyze_trace_response(
    url: str, *, status_code: int, body: str, probe_marker: str
) -> dict[str, Any] | None:
    """Detecta XST: TRACE habilitado E ecoando o corpo da requisição de volta.

    Uma requisição TRACE bem-comportada apenas ecoa a requisição recebida —
    se o marcador exclusivo enviado no corpo/headers da requisição aparece
    na resposta, o servidor de fato processa TRACE (não está bloqueado por
    um proxy/WAF na frente), confirmando a exposição.
    """
    if status_code != 200 or probe_marker not in body:
        return None
    return _finding(
        title="Método TRACE habilitado e ecoando a requisição (XST)",
        severity="medium",
        description=(
            f"O serviço em '{url}' aceita requisições TRACE e ecoa o conteúdo de volta. "
            "Combinado com XSS no mesmo domínio, isso pode ser usado para ler cookies "
            "marcados HttpOnly (Cross-Site Tracing)."
        ),
        evidence=f"TRACE {url} → HTTP 200, corpo contém o marcador da requisição.",
        recommendation="Desabilitar o método TRACE no servidor web.",
    )
