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
- **JWT fraco**: tokens JWT encontrados em páginas já rastreadas são
  decodificados (sem I/O extra — nenhuma requisição é enviada para isso) e
  analisados por três falhas estruturais clássicas: ``alg: none`` aceito,
  claim ``exp`` ausente (token nunca expira) e assinatura HS256 verificável
  com um segredo fraco/comum (computação local via HMAC, nunca contra a
  rede do alvo).

Funções puras: recebem respostas já obtidas pelo adapter, nunca fazem I/O.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
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


# --- JWT fraco (A07) --------------------------------------------------------

#: Casa um JWT (3 segmentos base64url separados por ponto) embutido em texto
#: livre — corpo de página/JSON, header ``Authorization: Bearer ...`` ou
#: ``Set-Cookie``. Exige o prefixo típico de um header JWT em Base64url
#: (``eyJ`` = ``{"`` codificado) para reduzir falso positivo.
#: Sem ``\b`` de fechamento: um JWT ``alg: none`` legítimo termina com a
#: assinatura vazia (terceiro segmento com zero caracteres) — nesse caso o
#: caractere anterior (o ponto) já não é "de palavra", então um ``\b`` final
#: nunca haveria fronteira para casar, e justamente o token mais crítico
#: (sem assinatura) deixaria de ser encontrado.
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")

#: Segredos HS256 comuns/triviais usados em tutoriais, exemplos e código não
#: revisado — testar localmente (HMAC, sem rede) se algum assina o token
#: encontrado prova que qualquer atacante poderia forjar tokens arbitrários.
COMMON_JWT_SECRETS: tuple[str, ...] = (
    "secret",
    "secretkey",
    "your-secret-key",
    "changeme",
    "password",
    "123456",
    "jwt_secret",
    "jwtsecret",
    "supersecret",
    "my-secret",
    "qwerty",
)


def find_jwt_candidates(text: str) -> list[str]:
    """Extrai candidatos a JWT (deduplicados, ordem preservada) de ``text``."""
    seen: set[str] = set()
    found: list[str] = []
    for match in JWT_RE.finditer(text or ""):
        token = match.group(0)
        if token not in seen:
            seen.add(token)
            found.append(token)
    return found


def _b64url_decode(segment: str) -> bytes | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:  # noqa: BLE001 — segmento inválido não deve derrubar o scan
        return None


def decode_jwt_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Decodifica header e payload de um JWT **sem validar a assinatura**.

    Usado só para inspecionar a estrutura (``alg``, ``exp``) — nunca para
    confiar no conteúdo como autenticado. Retorna ``None`` se o token não
    tiver o formato esperado (3 segmentos, header/payload JSON válidos).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])
    if header_raw is None or payload_raw is None:
        return None
    try:
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _hs256_signature(header_b64: str, payload_b64: str, secret: str) -> str:
    message = f"{header_b64}.{payload_b64}".encode("ascii")
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def find_weak_hs256_secret(token: str) -> str | None:
    """Tenta assinar ``token`` com segredos comuns — retorna o primeiro que casa.

    Puramente local (HMAC-SHA256 em memória): nenhuma requisição é feita ao
    alvo. Só se aplica a tokens ``alg: HS256``; outros algoritmos retornam
    ``None`` sem tentar nada.
    """
    decoded = decode_jwt_unverified(token)
    if decoded is None:
        return None
    header, _ = decoded
    if str(header.get("alg", "")).upper() != "HS256":
        return None
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        return None
    for secret in COMMON_JWT_SECRETS:
        candidate = _hs256_signature(header_b64, payload_b64, secret)
        if hmac.compare_digest(candidate, signature_b64):
            return secret
    return None


def analyze_jwt(token: str, *, source_url: str = "") -> dict[str, Any] | None:
    """Analisa um JWT encontrado em trânsito por falhas estruturais clássicas.

    Prioriza, em ordem de gravidade: ``alg: none`` aceito pelo emissor (o
    token em si já declara que não há assinatura) > segredo HS256 fraco
    (forjável) > ``exp`` ausente (sessão que nunca expira). Reporta só a
    primeira encontrada para não duplicar o mesmo token em vários findings.

    ``source_url``: a página onde o token foi visto (o adapter passa
    ``page.url`` do crawl) — só preenchido nos dois casos **forjáveis**
    (alg:none / segredo fraco), no formato padrão ``URL: ... | Parâmetro:
    '...'`` (``exploit/base.py:parse_web_target``), para que o motor de
    exploração saiba contra qual página reenviar um token forjado e observar
    se o comportamento muda. Omitido ("") quando o chamador não tem a URL —
    o finding fica sem coordenadas, e corretamente sem módulo de exploração.
    """
    decoded = decode_jwt_unverified(token)
    if decoded is None:
        return None
    header, payload = decoded
    alg = str(header.get("alg", "")).lower()
    shown = f"{token[:24]}...{token[-8:]}" if len(token) > 36 else token
    url_prefix = f"URL: {source_url} | Parâmetro: '' | " if source_url else ""

    if alg in {"none", ""}:
        return _finding(
            title="JWT com algoritmo 'none' aceito",
            severity="critical",
            description=(
                "Um JWT em trânsito declara o algoritmo 'none' (ou omite o "
                "algoritmo) no header — se o backend aceitar esse token sem "
                "assinatura, qualquer atacante pode forjar um token com "
                "qualquer claim (ex.: role=admin) sem conhecer segredo algum."
            ),
            evidence=f"{url_prefix}Token: {shown} | header.alg='{header.get('alg', '')}'",
            recommendation=(
                "Nunca aceitar 'alg: none'; fixar explicitamente o algoritmo "
                "esperado na verificação (nunca derivá-lo do próprio token) e "
                "usar uma biblioteca JWT atualizada."
            ),
            playbook_key="auth.jwt-weak",
        )

    weak_secret = find_weak_hs256_secret(token)
    if weak_secret is not None:
        return _finding(
            title="JWT assinado com segredo HS256 fraco/comum",
            severity="critical",
            description=(
                "A assinatura HS256 de um JWT em trânsito foi reproduzida "
                "localmente com um segredo comum/trivial — qualquer atacante "
                "com a mesma lista de segredos pode forjar tokens arbitrários "
                "(incluindo elevar privilégios ou se autenticar como outro usuário)."
            ),
            evidence=f"{url_prefix}Token: {shown} | segredo testado localmente (HMAC): '{weak_secret}'",
            recommendation=(
                "Usar um segredo HS256 longo, aleatório e exclusivo (≥32 bytes), "
                "nunca um valor de exemplo/tutorial, e considerar migrar para "
                "RS256/ES256 (par de chaves assimétrico)."
            ),
            playbook_key="auth.jwt-weak",
        )

    if "exp" not in payload:
        return _finding(
            title="JWT sem claim de expiração ('exp')",
            severity="medium",
            description=(
                "Um JWT em trânsito não possui a claim 'exp' — o token nunca "
                "expira, então um token vazado/roubado permanece válido "
                "indefinidamente, ampliando a janela de exploração de qualquer "
                "comprometimento de sessão."
            ),
            evidence=f"Token: {shown} | claims do payload: {sorted(payload.keys())}",
            recommendation=(
                "Sempre incluir 'exp' com um tempo de vida curto, e usar "
                "refresh tokens (revogáveis) para renovar a sessão."
            ),
            playbook_key="auth.jwt-weak",
        )

    return None


# --- Forja de JWT (usada pelo motor de exploração, nunca pela detecção) ----

#: Nomes de claim que, se já presentes no payload original, costumam
#: controlar privilégio — elevamos só os que **já existem** (nunca inventamos
#: estrutura nova: um claim que o emissor nunca usa não teria efeito real e
#: tornaria a "prova" especulativa).
_PRIVILEGE_CLAIM_NAMES = (
    "role",
    "roles",
    "is_admin",
    "isadmin",
    "admin",
    "scope",
    "scopes",
    "permissions",
    "type",
)


def elevate_claims(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Retorna ``(payload_elevado, claims_alteradas)`` — só altera claims já existentes.

    O tipo original de cada valor é preservado (bool→``True``, lista→
    ``["admin"]``, string→``"admin"``) para o token forjado continuar
    estruturalmente plausível para o backend que o emitiu.
    """
    elevated = dict(payload)
    changed: list[str] = []
    for key in list(elevated.keys()):
        if key.lower() not in _PRIVILEGE_CLAIM_NAMES:
            continue
        value = elevated[key]
        if isinstance(value, bool):
            elevated[key] = True
        elif isinstance(value, list):
            elevated[key] = ["admin"]
        else:
            elevated[key] = "admin"
        changed.append(key)
    return elevated, changed


def forge_jwt(header: dict[str, Any], payload: dict[str, Any], *, secret: str | None) -> str:
    """Monta um JWT com ``header``/``payload`` dados — ``secret=None`` → ``alg: none``.

    Função pura (sem I/O): usada pelo motor de exploração para construir o
    token que será reenviado via ``ExploitContext.fetch`` — a forja em si não
    é a exploração, só o reenvio contra o alvo é.
    """
    forged_header = dict(header)
    if secret is None:
        forged_header["alg"] = "none"
    header_b64 = _b64url(json.dumps(forged_header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    if secret is None:
        return f"{header_b64}.{payload_b64}."
    signature_b64 = _hs256_signature(header_b64, payload_b64, secret)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
