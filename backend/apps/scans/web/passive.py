"""Checagens passivas de segurança web (Fase 4): headers, cookies, CORS.

Funções puras — recebem dados já obtidos pelo adapter (headers, cookies já
normalizados em dicts simples, corpo) e retornam findings. Nenhuma delas faz
I/O; a coleta (incluindo o parsing correto de múltiplos ``Set-Cookie`` via
``requests.cookies``, que ``dict(response.headers)`` corromperia por
concatenar todos em uma string) vive em ``adapters.WebScanAdapter``.
"""

from __future__ import annotations

from typing import Any

#: Headers de segurança verificados: nome → (severidade se ausente, propósito).
_SECURITY_HEADERS: dict[str, tuple[str, str]] = {
    "Strict-Transport-Security": (
        "high",
        "Força HTTPS em conexões futuras, protegendo contra downgrade/sslstrip.",
    ),
    "Content-Security-Policy": (
        "medium",
        "Restringe as origens de script/estilo/etc. que o navegador pode carregar, mitigando XSS.",
    ),
    "X-Frame-Options": (
        "medium",
        "Previne clickjacking (embutir a página em um <iframe> de outro site).",
    ),
    "X-Content-Type-Options": (
        "low",
        "Evita que o navegador “adivinhe” o tipo de conteúdo (MIME sniffing).",
    ),
    "Referrer-Policy": (
        "low",
        "Controla quanto da URL de origem vaza para outros sites via header Referer.",
    ),
    "Permissions-Policy": (
        "low",
        "Restringe o uso de APIs sensíveis do navegador (câmera, geolocalização etc.).",
    ),
}

_DIR_LISTING_MARKERS = ("Index of /", "<title>Index of", "Directory Listing For")


def _finding(
    *,
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: str,
    recommendation: str,
    playbook_key: str = "",
) -> dict[str, Any]:
    finding = {
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }
    if playbook_key:
        finding["playbook_key"] = playbook_key
    return finding


def analyze_security_headers(headers: dict[str, str], *, is_https: bool) -> list[dict[str, Any]]:
    """Reporta headers de segurança ausentes na resposta (category ``web-headers``)."""
    lower_present = {k.lower() for k in headers}
    findings = []
    for header, (severity, purpose) in _SECURITY_HEADERS.items():
        if header == "Strict-Transport-Security" and not is_https:
            continue  # HSTS só faz sentido sobre HTTPS
        if header.lower() in lower_present:
            continue
        findings.append(
            _finding(
                title=f"Header de segurança ausente: {header}",
                severity=severity,
                category="web-headers",
                description=f"A resposta não inclui o header '{header}'. {purpose}",
                evidence=f"Header '{header}' não encontrado na resposta HTTP.",
                recommendation=f"Adicionar o header '{header}' às respostas do serviço.",
            )
        )
    return findings


def analyze_cookies(cookies: list[dict[str, Any]], *, is_https: bool) -> list[dict[str, Any]]:
    """Reporta cookies sem Secure/HttpOnly/SameSite adequados (category ``cookie``).

    Args:
        cookies: Lista de ``{"name", "secure", "httponly", "samesite"}`` já
            extraídos pelo adapter via ``response.cookies`` (RequestsCookieJar) —
            a única forma confiável de inspecionar múltiplos ``Set-Cookie``,
            já que concatená-los numa string (``dict(response.headers)``)
            perde a separação entre cookies.
    """
    findings = []
    for cookie in cookies:
        name = cookie.get("name", "?")
        missing = []
        if is_https and not cookie.get("secure"):
            missing.append("Secure")
        if not cookie.get("httponly"):
            missing.append("HttpOnly")
        if not cookie.get("samesite"):
            missing.append("SameSite")
        if not missing:
            continue
        findings.append(
            _finding(
                title=f"Cookie '{name}' sem flags de segurança adequadas",
                severity="medium",
                category="cookie",
                description=(
                    f"O cookie '{name}' não define: {', '.join(missing)}. Isso aumenta "
                    "a exposição a roubo de sessão via XSS (sem HttpOnly), interceptação "
                    "em trânsito (sem Secure) ou CSRF (sem SameSite)."
                ),
                evidence=(
                    f"Cookie '{name}': secure={cookie.get('secure')}, "
                    f"httponly={cookie.get('httponly')}, samesite={cookie.get('samesite')}."
                ),
                recommendation=(
                    "Definir Secure (em HTTPS), HttpOnly e SameSite=Lax (ou Strict) em "
                    "todos os cookies de sessão/autenticação."
                ),
            )
        )
    return findings


def analyze_cors(headers: dict[str, str], *, probe_origin: str) -> list[dict[str, Any]]:
    """Reporta CORS mal configurado (category ``cors``).

    Args:
        headers: Headers da resposta a uma requisição que enviou
            ``Origin: <probe_origin>`` — usado para detectar reflexão de
            origem arbitrária, não apenas a presença estática do header.
        probe_origin: A origem (fabricada, nunca resolvível) enviada na
            requisição de teste.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    acao = lower.get("access-control-allow-origin")
    if not acao:
        return []

    acac = (lower.get("access-control-allow-credentials") or "").strip().lower() == "true"

    if acao == "*" and acac:
        return [
            _finding(
                title="CORS permite qualquer origem com credenciais",
                severity="high",
                category="cors",
                description=(
                    "A resposta combina 'Access-Control-Allow-Origin: *' com "
                    "'Access-Control-Allow-Credentials: true' — combinação inválida pela "
                    "especificação (navegadores devem rejeitá-la), mas indica configuração "
                    "de CORS fundamentalmente insegura."
                ),
                evidence="Access-Control-Allow-Origin: * ; Access-Control-Allow-Credentials: true",
                recommendation="Usar uma allowlist explícita de origens confiáveis, nunca '*' com credenciais.",
                playbook_key="cors.misconfig",
            )
        ]

    if acao == probe_origin:
        return [
            _finding(
                title="CORS reflete a Origin da requisição sem validação",
                severity="high" if acac else "medium",
                category="cors",
                description=(
                    f"O servidor ecoou de volta uma origem arbitrária e nunca vista "
                    f"antes ('{probe_origin}') no header Access-Control-Allow-Origin"
                    + (" e permite credenciais" if acac else "")
                    + " — sugere que qualquer origem é aceita, não uma allowlist real."
                ),
                evidence=f"Origin enviada: {probe_origin} → Access-Control-Allow-Origin: {acao}",
                recommendation="Validar a origem contra uma allowlist fixa antes de refleti-la no header.",
                playbook_key="cors.misconfig",
            )
        ]

    return []


def analyze_directory_listing(url: str, body: str) -> dict[str, Any] | None:
    """Detecta listagem de diretório habilitada (category ``exposure``)."""
    if not any(marker in body for marker in _DIR_LISTING_MARKERS):
        return None
    return _finding(
        title="Directory listing habilitado",
        severity="medium",
        category="exposure",
        description=f"O servidor expõe a listagem de arquivos do diretório em '{url}'.",
        evidence="Corpo da resposta contém marcador de listagem de diretório (ex.: 'Index of /').",
        recommendation="Desabilitar a listagem de diretórios no servidor web (ex.: 'Options -Indexes' no Apache).",
    )
