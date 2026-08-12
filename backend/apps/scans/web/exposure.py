"""Checagem de paths sensíveis expostos (Fase 4 — category ``exposure``).

Regra pura: decide se um path sensível está de fato exposto comparando a
resposta contra um **baseline** de "não encontrado" (um path aleatório que
certamente não existe). Sem essa comparação, um servidor que devolve
``200`` para qualquer path (SPA com catch-all de rota, página de erro
customizada sem status 404 correto) geraria falso positivo em todo path
testado — o baseline isola exatamente esse comportamento.
"""

from __future__ import annotations

from typing import Any

#: Diferença de tamanho (bytes) abaixo da qual duas respostas são
#: consideradas "a mesma página" para fins de comparação com o baseline.
_SIMILAR_LENGTH_THRESHOLD = 32


def _looks_like_baseline(
    *, status_code: int, body: str, baseline_status: int, baseline_body: str
) -> bool:
    """True se a resposta parece ser a mesma página de "não encontrado" do baseline."""
    if status_code != baseline_status:
        return False
    return abs(len(body) - len(baseline_body)) <= _SIMILAR_LENGTH_THRESHOLD


def classify_exposure(
    *,
    path: str,
    signature: str | None,
    status_code: int,
    body: str,
    baseline_status: int,
    baseline_body: str,
) -> dict[str, Any] | None:
    """Decide se ``path`` está exposto, ou ``None`` se não houver evidência suficiente.

    Args:
        path: Path sensível testado (ex.: ``/.git/HEAD``).
        signature: Substring esperada no corpo quando o path realmente
            existe (``data/web_paths.SENSITIVE_PATHS``); ``None`` quando o
            próprio status já é significativo.
        status_code: Status da resposta ao path sensível.
        body: Corpo da resposta ao path sensível.
        baseline_status: Status de um path aleatório inexistente no mesmo host.
        baseline_body: Corpo da resposta ao path aleatório.

    Returns:
        Dict de finding (category ``exposure``) ou ``None``.
    """
    if status_code in (401, 403, 404, 429, 500, 501, 502, 503):
        return None  # bloqueado/erro — não é uma exposição confirmada

    if _looks_like_baseline(
        status_code=status_code,
        body=body,
        baseline_status=baseline_status,
        baseline_body=baseline_body,
    ):
        return None  # provável soft-404: servidor devolve 200 pra qualquer path

    if signature is not None and signature not in body:
        return None  # path "respondeu" mas o conteúdo não bate com a assinatura esperada

    evidence = f"GET {path} → HTTP {status_code}"
    if signature:
        evidence += f", corpo contém a assinatura esperada ('{signature}')."
    else:
        evidence += ", resposta distinta do baseline de path inexistente."

    return {
        "title": f"Path sensível acessível: {path}",
        "severity": "high",
        "category": "exposure",
        "description": (
            f"O path '{path}' está acessível publicamente e pode expor "
            "credenciais, código-fonte, configuração ou dados de backup."
        ),
        "evidence": evidence,
        "recommendation": (
            f"Remover ou restringir o acesso a '{path}' (ex.: bloquear no servidor "
            "web, mover para fora do webroot, ou exigir autenticação)."
        ),
    }
