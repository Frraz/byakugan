"""Detecção de CSRF (Cross-Site Request Forgery) — OWASP A01, CWE-352.

Checagem **puramente estática**, sem nenhuma requisição extra: o crawler já
obteve os formulários (``web.crawler.extract_links_and_forms``) durante o
mapeamento normal do site. Aqui só decidimos se um formulário que muda
estado no servidor (``method="POST"``) tem algum campo de token anti-CSRF
entre seus inputs — se não tiver, submeter esse formulário a partir de um
site de terceiros (ex.: via uma tag ``<form>`` escondida numa página
maliciosa) forçaria o navegador da vítima, já autenticado, a executar a
ação sem que ela perceba.

Heurística conservadora: só formulários ``POST`` são considerados
"mudam estado" (GET deveria ser sempre seguro/idempotente por definição
HTTP — o restante do motor já assume isso, ex.: ``_collect_injection_points``
só testa formulários GET). Não submete nada — apenas inspeciona os nomes
dos campos já coletados pelo crawl.
"""

from __future__ import annotations

from typing import Any

#: Substrings (case-insensitive) de nomes de campo que indicam um token
#: anti-CSRF — cobre as convenções mais comuns (Django, Rails, .NET, Spring,
#: Laravel, genérico).
_CSRF_TOKEN_NAME_MARKERS = (
    "csrf",
    "xsrf",
    "_token",
    "authenticity_token",
    "requestverificationtoken",
    "anti-forgery",
    "antiforgery",
    "nonce",
)


def _finding(
    *,
    title: str,
    severity: str,
    description: str,
    evidence: str,
    recommendation: str,
    playbook_key: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "category": "access-control",
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "playbook_key": playbook_key,
    }


def has_csrf_token(inputs: list[str]) -> bool:
    """True se algum nome de campo do formulário parece um token anti-CSRF."""
    return any(
        marker in str(name).lower() for name in inputs for marker in _CSRF_TOKEN_NAME_MARKERS
    )


def detect_missing_csrf_token(
    *, form: dict[str, Any], session_cookie_samesite: str | None = None
) -> dict[str, Any] | None:
    """Decide se um formulário ``POST`` está vulnerável a CSRF.

    Args:
        form: ``{"action", "method", "inputs"}`` do crawler.
        session_cookie_samesite: valor do atributo ``SameSite`` do cookie de
            sessão observado no mesmo host (se algum), usado só para ajustar
            a severidade — ``Strict``/``Lax`` mitiga parcialmente mesmo sem
            token, então vira ``medium`` em vez de ``high``.

    Returns:
        Finding (category ``access-control``) ou ``None`` quando o
        formulário não é ``POST`` ou já tem um campo de token.
    """
    if str(form.get("method", "")).upper() != "POST":
        return None
    inputs = form.get("inputs", [])
    if has_csrf_token(inputs):
        return None

    samesite = (session_cookie_samesite or "").lower()
    mitigated = samesite in {"strict", "lax"}
    severity = "medium" if mitigated else "high"

    return _finding(
        title="Formulário sem proteção CSRF",
        severity=severity,
        description=(
            "Um formulário que altera estado no servidor (POST) não possui "
            "nenhum campo de token anti-CSRF entre seus inputs — um site "
            "malicioso pode forçar o navegador de uma vítima autenticada a "
            "submeter esta ação sem que ela perceba (Cross-Site Request Forgery)."
            + (
                " O cookie de sessão usa SameSite="
                f"{session_cookie_samesite}, o que mitiga parcialmente o risco "
                "em navegadores modernos, mas não substitui o token."
                if mitigated
                else ""
            )
        ),
        evidence=(
            f"URL: {form.get('action', '')} | Parâmetro: '' | Formulário POST com "
            f"campos {list(inputs)}, nenhum reconhecido como token anti-CSRF."
        ),
        recommendation=(
            "Gerar um token anti-CSRF único por sessão/requisição, incluí-lo "
            "como campo oculto no formulário e validá-lo no servidor antes de "
            "processar a ação; usar cookies de sessão com SameSite=Strict/Lax "
            "como defesa em profundidade adicional."
        ),
        playbook_key="access-control.csrf",
    )
