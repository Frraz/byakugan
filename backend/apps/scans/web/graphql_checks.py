"""Detecção de introspecção GraphQL exposta (OWASP A05:2021 → A02:2025, CWE-215).

Introspecção é um recurso legítimo do GraphQL (lista todo o schema: tipos,
campos, queries/mutations disponíveis) — útil em desenvolvimento, mas em
produção vira um mapa completo da API para um atacante, incluindo campos e
mutations que nunca foram documentados publicamente.

Detecção **estritamente GET** (RN016: só idempotente) — a query de
introspecção é somente leitura (não muda estado), e muitos servidores
GraphQL aceitam `?query=` via GET além do POST usual; quando o endpoint só
aceita POST, o Byakugan simplesmente não o testa (honestidade técnica: sem
exploração via escrita para contornar a limitação). Funções puras: recebem
a resposta já obtida pelo adapter, nunca fazem I/O.
"""

from __future__ import annotations

from typing import Any

#: Candidatos a endpoint GraphQL — convenções mais comuns.
GRAPHQL_PATHS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/console",
)

#: Query de introspecção mínima — só pede o nome do tipo raiz de query, o
#: suficiente para provar que a introspecção está habilitada sem baixar o
#: schema inteiro (mantém o probe leve/não-destrutivo).
INTROSPECTION_QUERY = "{__schema{queryType{name}}}"


def build_introspection_url(base_url: str, path: str) -> str:
    """Monta a URL GET de introspecção para ``path`` (relativo a ``base_url``)."""
    from urllib.parse import urlencode, urljoin

    query = urlencode({"query": INTROSPECTION_QUERY})
    return f"{urljoin(base_url, path)}?{query}"


def _finding(*, title: str, evidence: str, playbook_key: str) -> dict[str, Any]:
    return {
        "title": title,
        "severity": "medium",
        "category": "exposure",
        "description": (
            "O endpoint GraphQL responde a uma query de introspecção sem "
            "exigir autenticação — um atacante pode enumerar todo o schema "
            "(tipos, campos, queries e mutations disponíveis, incluindo os "
            "não documentados publicamente) e usá-lo para mapear a superfície "
            "de ataque da API com precisão."
        ),
        "evidence": evidence,
        "recommendation": (
            "Desabilitar introspecção em produção (a maioria dos frameworks "
            "GraphQL tem uma flag dedicada, ex.: `introspection: false`) ou "
            "restringi-la a clientes autenticados/internos."
        ),
        "playbook_key": playbook_key,
    }


def classify_introspection(*, url: str, status_code: int, body: str) -> dict[str, Any] | None:
    """Decide se a resposta confirma introspecção GraphQL habilitada.

    Positivo só quando o JSON de resposta traz a estrutura esperada
    (``"queryType"`` dentro de ``"__schema"``) — um 404/erro genérico da
    aplicação (ex.: SPA com catch-all) não deveria casar essa assinatura.
    """
    if status_code != 200:
        return None
    if '"__schema"' not in body or '"queryType"' not in body:
        return None
    return _finding(
        title="Introspecção GraphQL habilitada sem autenticação",
        # Formato "URL: ... | Parâmetro: '...'" (mesmo contrato de todo finding
        # web — ver ``exploit/base.py:parse_web_target``) para o motor de
        # exploração conseguir reenviar uma query de introspecção mais ampla e
        # extrair uma amostra dos nomes de tipo reais (``exploit/graphql.py``).
        evidence=(
            f"URL: {url} | Parâmetro: '' | GET {url} → HTTP 200, resposta contém "
            "'__schema.queryType' (schema enumerável)."
        ),
        playbook_key="exposure.graphql-introspection",
    )
