"""Detecção de Identification & Authentication Failures (OWASP A07) — Fase B.

Checagens não-destrutivas em torno de formulários de login:

- **User enumeration**: a resposta de erro revela se o usuário existe (mensagens
  do tipo "usuário não encontrado" vs. "senha incorreta"), permitindo enumerar
  contas válidas.
- **Missing rate limiting / lockout**: um número **mínimo e limitado** de
  tentativas com credenciais claramente inválidas nunca é barrado (nenhum 429/
  bloqueio) — indício de ausência de proteção contra força bruta. O burst é
  minúsculo e usa credenciais obviamente falsas (não compromete conta alguma);
  a decisão aqui é pura, o burst limitado fica no adapter (gated em aggressive).

Funções puras: recebem respostas já obtidas pelo adapter, nunca fazem I/O.
"""

from __future__ import annotations

import re
from typing import Any

#: Marcadores de que a mensagem de erro distingue "usuário inexistente" de
#: "senha incorreta" — a assinatura clássica de user enumeration.
_USERNAME_DISCLOSURE_PATTERNS = (
    re.compile(r"user(name)?\s+(does not exist|not found|unknown|is not registered)", re.I),
    re.compile(r"no\s+(such\s+)?(user|account)\s+(found|exists)", re.I),
    re.compile(r"usu[aá]rio\s+(n[aã]o\s+(existe|encontrado|cadastrado)|inexistente)", re.I),
    re.compile(r"conta\s+n[aã]o\s+(existe|encontrada)", re.I),
    re.compile(r"e-?mail\s+n[aã]o\s+(cadastrado|encontrado|registrado)", re.I),
    re.compile(r"invalid\s+username", re.I),
)

#: Indícios de que a tentativa foi barrada por rate limiting/lockout (bom sinal).
_RATE_LIMIT_MARKERS = (
    "too many",
    "rate limit",
    "muitas tentativas",
    "tente novamente mais tarde",
    "try again later",
    "temporarily locked",
    "conta bloqueada",
    "account locked",
    "captcha",
)

#: Nomes de campo típicos de senha — identificam um formulário de login.
PASSWORD_FIELD_NAMES = ("password", "passwd", "pwd", "senha", "pass")


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
        "category": "auth",
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "playbook_key": playbook_key,
    }


def is_login_form(form: dict[str, Any]) -> bool:
    """True se o formulário aparenta ser de login (tem um campo de senha)."""
    inputs = [str(name).lower() for name in form.get("inputs", [])]
    return any(any(pw in name for pw in PASSWORD_FIELD_NAMES) for name in inputs)


def detect_user_enumeration(*, url: str, body: str) -> dict[str, Any] | None:
    """Detecta mensagem de erro que revela existência de usuário (enumeration)."""
    for pattern in _USERNAME_DISCLOSURE_PATTERNS:
        match = pattern.search(body)
        if match:
            return _finding(
                title="Possível enumeração de usuários no login",
                severity="medium",
                description=(
                    "A resposta de erro de autenticação distingue 'usuário "
                    "inexistente' de 'senha incorreta' — um atacante pode enumerar "
                    "contas válidas antes de tentar força bruta ou phishing "
                    "direcionado."
                ),
                evidence=(
                    f"URL: {url} | Parâmetro: '' | Mensagem reveladora na resposta: "
                    f"'{match.group(0)[:100]}'."
                ),
                recommendation=(
                    "Usar uma mensagem de erro genérica e idêntica para "
                    "usuário/senha inválidos ('credenciais inválidas'), e igualar o "
                    "tempo de resposta entre os dois casos."
                ),
                playbook_key="auth.user-enumeration",
            )
    return None


def was_rate_limited(*, status_code: int, body: str) -> bool:
    """True se a resposta indica rate limiting/lockout (429 ou marcador no corpo)."""
    if status_code == 429:
        return True
    lowered = body.lower()
    return any(marker in lowered for marker in _RATE_LIMIT_MARKERS)


def detect_missing_rate_limit(
    *, url: str, attempts: list[tuple[int, str]]
) -> dict[str, Any] | None:
    """Decide, a partir de um burst limitado de tentativas, se falta rate limiting.

    ``attempts``: lista ``(status_code, body)`` das tentativas de login com
    credenciais inválidas (o adapter faz um burst mínimo, ex.: 5, gated em
    aggressive). Se **nenhuma** foi barrada (nenhum 429/lockout), reporta a
    ausência de proteção contra força bruta.
    """
    if len(attempts) < 3:
        return None
    if any(was_rate_limited(status_code=status, body=body) for status, body in attempts):
        return None
    return _finding(
        title="Ausência de rate limiting / bloqueio no login",
        severity="medium",
        description=(
            f"{len(attempts)} tentativas de login consecutivas com credenciais "
            "inválidas não foram barradas (nenhum HTTP 429, bloqueio de conta ou "
            "CAPTCHA) — a aplicação não limita tentativas de autenticação, "
            "facilitando ataques de força bruta e credential stuffing."
        ),
        evidence=(
            f"URL: {url} | Parâmetro: '' | {len(attempts)} tentativas inválidas, "
            f"status observados: {[s for s, _ in attempts]}, sem barramento."
        ),
        recommendation=(
            "Implementar rate limiting por IP/conta, bloqueio temporário "
            "progressivo após N falhas, CAPTCHA e MFA nos fluxos de autenticação."
        ),
        playbook_key="auth.no-rate-limit",
    )
