"""Detecção de Broken Access Control (OWASP A01) — Fase B.

Duas classes de falha de controle de acesso detectáveis remotamente e de forma
não-destrutiva (só GET idempotente):

- **Forced browsing**: endpoints administrativos/de gestão acessíveis sem
  autenticação (retornam conteúdo real, não o soft-404 do baseline).
- **IDOR** (Insecure Direct Object Reference): trocar um identificador
  numérico/sequencial num parâmetro devolve o objeto de *outro* usuário —
  heurística conservadora para não gerar falso positivo em listagens públicas.

Funções puras: recebem respostas já obtidas pelo adapter (o único seam de
rede é ``WebScanAdapter._fetch``), nunca fazem I/O. Comparação com baseline
soft-404 espelha ``web/exposure.classify_exposure``.
"""

from __future__ import annotations

import re
from typing import Any

#: Marcadores que indicam que a resposta é, ela própria, uma tela de login /
#: negação de acesso (ou seja, o controle de acesso ESTÁ funcionando) — não
#: contam como forced browsing bem-sucedido.
_AUTH_WALL_MARKERS = (
    "sign in",
    "log in",
    "login",
    "entrar",
    "faça login",
    "autentic",
    "unauthorized",
    "não autorizado",
    "acesso negado",
    "forbidden",
    "please authenticate",
)

#: Marcadores de que a resposta é de fato um painel/área administrativa real
#: (aumenta a confiança de que o acesso não-autenticado teve sucesso).
_ADMIN_CONTENT_MARKERS = (
    "dashboard",
    "admin",
    "logout",
    "sair",
    "settings",
    "configurações",
    "users",
    "usuários",
    "manage",
    "gerenciar",
    "console",
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


def _looks_like_auth_wall(body: str) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in _AUTH_WALL_MARKERS)


def _looks_like_admin_content(body: str) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in _ADMIN_CONTENT_MARKERS)


def classify_forced_browsing(
    *,
    url: str,
    path: str,
    status_code: int,
    body: str,
    baseline_status: int,
    baseline_body: str,
) -> dict[str, Any] | None:
    """Decide se um endpoint administrativo está acessível sem autenticação.

    Positivo quando o path devolve 200 com conteúdo (diferente do soft-404 do
    baseline) e a resposta **não** é uma tela de login/negação — ou seja, o
    conteúdo restrito foi servido a um cliente não-autenticado. Redirecionar
    para login (3xx) ou responder 401/403 é o comportamento correto e não gera
    finding.
    """
    if status_code != 200:
        return None
    # Baseline (path aleatório) também 200 ⇒ o servidor responde 200 pra tudo
    # (soft-404); só reporta se o corpo for materialmente diferente e "admin".
    if baseline_status == 200 and _similar_length(body, baseline_body):
        return None
    if not body.strip():
        return None
    if _looks_like_auth_wall(body):
        return None
    confidence_admin = _looks_like_admin_content(body)
    return _finding(
        title=f"Endpoint administrativo acessível sem autenticação: {path}",
        severity="high" if confidence_admin else "medium",
        description=(
            "Um endpoint administrativo/de gestão respondeu com conteúdo a uma "
            "requisição não-autenticada, em vez de exigir login (redirect/401/403) "
            "— indício de Broken Access Control: funcionalidade sensível exposta a "
            "qualquer visitante."
        ),
        evidence=(
            f"URL: {url} | Parâmetro: '' | GET {path} devolveu HTTP {status_code} "
            f"com conteúdo ({len(body)} bytes)"
            + (" contendo marcadores de área administrativa" if confidence_admin else "")
            + "."
        ),
        recommendation=(
            "Exigir autenticação e autorização (RBAC) em todos os endpoints "
            "administrativos; negar por padrão (deny-by-default) e validar a "
            "sessão no servidor, nunca só escondendo o link na UI."
        ),
        playbook_key="access-control.forced-browsing",
    )


def _similar_length(a: str, b: str) -> bool:
    """True se dois corpos têm tamanho parecido (mesma página soft-404)."""
    longer = max(len(a), len(b), 1)
    return abs(len(a) - len(b)) <= max(64, int(longer * 0.05))


_NUMERIC_RE = re.compile(r"^\d+$")


def is_idor_candidate(value: str) -> bool:
    """True se o valor do parâmetro parece um identificador de objeto (numérico)."""
    return bool(value) and bool(_NUMERIC_RE.match(value.strip()))


def next_id(value: str) -> str:
    """Deriva um id vizinho para o teste de IDOR (id+1, ou id-1 se for 0/1)."""
    n = int(value)
    return str(n + 1) if n > 1 else str(n + 1)


def detect_idor(
    *,
    url: str,
    param: str,
    original_value: str,
    original_status: int,
    original_body: str,
    variant_value: str,
    variant_status: int,
    variant_body: str,
) -> dict[str, Any] | None:
    """Heurística conservadora de IDOR ao variar um id numérico.

    Positivo quando ambos (id original e id vizinho) retornam 200 com conteúdo
    **substancial e diferente** entre si e de estrutura semelhante — sinal de
    que objetos de identificadores distintos são servidos sem checagem de
    propriedade. Conservador de propósito: exige corpos não-triviais e
    diferentes para evitar falso positivo em páginas públicas/estáticas.
    """
    if original_status != 200 or variant_status != 200:
        return None
    if len(original_body) < 128 or len(variant_body) < 128:
        return None
    if original_body == variant_body:
        return None
    # Objetos distintos costumam ter o MESMO gabarito e tamanho parecido, com
    # conteúdo diferente — não uma página de erro (que seria bem menor/diferente).
    if not _similar_length(original_body, variant_body):
        return None
    return _finding(
        title=f"Possível IDOR no parâmetro '{param}'",
        severity="high",
        description=(
            "Alterar um identificador numérico no parâmetro devolveu um objeto "
            "diferente, de estrutura semelhante, sem exigir autorização — indício "
            "de Insecure Direct Object Reference (IDOR): um usuário pode acessar "
            "registros de outro apenas trocando o id."
        ),
        evidence=(
            f"URL: {url} | Parâmetro: '{param}' | {param}={original_value} e "
            f"{param}={variant_value} retornaram HTTP 200 com corpos distintos de "
            f"tamanho semelhante ({len(original_body)}/{len(variant_body)} bytes)."
        ),
        recommendation=(
            "Validar no servidor que o objeto solicitado pertence ao usuário "
            "autenticado (checagem de propriedade/ACL por requisição); preferir "
            "identificadores não-sequenciais (UUID) e negar por padrão."
        ),
        playbook_key="access-control.idor",
    )
