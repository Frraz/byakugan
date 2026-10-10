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

#: Mapeia prefixos de path sensível ao playbook de exploração correspondente
#: (aba Evidências). Sem módulo de exploração automatizado por ora — o playbook
#: mostra "como explorar / até onde vai" manualmente.
_PATH_PLAYBOOKS: tuple[tuple[str, str], ...] = (
    ("/.git", "exposure.git"),
    ("/.env", "exposure.env"),
    ("/actuator", "exposure.actuator"),
    ("/swagger", "exposure.api-docs"),
    ("/openapi", "exposure.api-docs"),
    ("/api-docs", "exposure.api-docs"),
    ("/v2/api-docs", "exposure.api-docs"),
    ("/v3/api-docs", "exposure.api-docs"),
    ("/api/swagger.json", "exposure.api-docs"),
)


def _playbook_for_path(path: str) -> str:
    """Retorna a ``playbook_key`` do path sensível (ou ``""`` se não houver)."""
    for prefix, key in _PATH_PLAYBOOKS:
        if path.startswith(prefix):
            return key
    return ""


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
        "playbook_key": _playbook_for_path(path),
    }


#: Marcadores que, juntos, confirmam que um corpo é de fato um source map
#: (JSON com o formato da especificação), não apenas um 404 coincidente.
_SOURCE_MAP_MARKERS = ('"version"', '"sources"', '"mappings"')


def classify_source_map(
    *,
    script_url: str,
    status_code: int,
    body: str,
    baseline_status: int,
    baseline_body: str,
) -> dict[str, Any] | None:
    """Decide se o source map (``.js.map``) de um script rastreado está exposto.

    Mesma lógica de baseline de ``classify_exposure`` (evita falso positivo em
    servidores que respondem 200 para qualquer path), mais a verificação de
    que o corpo é de fato um source map (não um HTML de erro customizado).
    Um source map exposto revela o código-fonte original (não minificado) —
    comentários, nomes de variáveis, lógica de negócio e, com frequência,
    endpoints de API não documentados.
    """
    if status_code in (401, 403, 404, 429, 500, 501, 502, 503):
        return None
    if _looks_like_baseline(
        status_code=status_code,
        body=body,
        baseline_status=baseline_status,
        baseline_body=baseline_body,
    ):
        return None
    if not all(marker in body for marker in _SOURCE_MAP_MARKERS):
        return None

    map_url = f"{script_url}.map" if not script_url.endswith(".map") else script_url
    return {
        "title": "Source map exposto revela código-fonte original",
        "severity": "medium",
        "category": "exposure",
        "description": (
            "Um arquivo de source map (.js.map) de um script da aplicação está "
            "acessível publicamente — ele reconstrói o código JavaScript "
            "original (não minificado), incluindo comentários, nomes de "
            "variáveis/funções e, com frequência, lógica de negócio ou "
            "endpoints de API que não deveriam ser visíveis no cliente."
        ),
        # Formato "URL: ... | Parâmetro: '...'" (mesmo contrato de todo finding
        # web — ver ``exploit/base.py:parse_web_target``) para que o motor de
        # exploração consiga derivar a URL do .map e baixá-lo de novo para
        # extrair uma amostra do código-fonte vazado (``exploit/source_map.py``).
        "evidence": (
            f"URL: {map_url} | Parâmetro: '' | GET {map_url} → HTTP {status_code}, "
            "corpo contém a estrutura de um source map válido."
        ),
        "recommendation": (
            "Não publicar arquivos .map em produção (gerá-los só para uso "
            "interno de debug, fora do webroot público) ou, no mínimo, "
            "restringir o acesso a eles."
        ),
        "playbook_key": "exposure.source-map",
    }
