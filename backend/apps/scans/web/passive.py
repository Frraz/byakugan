"""Checagens passivas de segurança web (Fase 4): headers, cookies, CORS.

Funções puras — recebem dados já obtidos pelo adapter (headers, cookies já
normalizados em dicts simples, corpo) e retornam findings. Nenhuma delas faz
I/O; a coleta (incluindo o parsing correto de múltiplos ``Set-Cookie`` via
``requests.cookies``, que ``dict(response.headers)`` corromperia por
concatenar todos em uma string) vive em ``adapters.WebScanAdapter``.
"""

from __future__ import annotations

import re
from typing import Any

from .auth_checks import is_login_form

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


def _parse_csp(csp: str) -> dict[str, list[str]]:
    """Parseia um header CSP em ``{diretiva: [fontes]}`` (minúsculas, sem I/O)."""
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


#: Origens que efetivamente permitem carregar script de **qualquer lugar** —
#: um wildcard total ou um wildcard de esquema inteiro, ambos anulam a
#: proteção da CSP contra origens de script maliciosas.
_CSP_WILDCARD_SOURCES = ("*", "http:", "https:", "data:")


def analyze_csp_quality(csp: str) -> list[dict[str, Any]]:
    """Avalia a **qualidade** de uma CSP já presente (category ``web-headers``).

    Complementar a ``analyze_security_headers`` (que só checa ausência/
    presença): uma CSP tecnicamente presente, mas com diretivas fracas, não
    oferece proteção real contra XSS/clickjacking — um achado comum e de
    alto valor em pentest real. Opera só sobre o header já obtido no probe
    base (nenhuma requisição extra).
    """
    directives = _parse_csp(csp)
    if not directives:
        return []

    findings: list[dict[str, Any]] = []
    script_src = directives.get("script-src", directives.get("default-src", []))
    object_src = directives.get("object-src", directives.get("default-src", []))
    frame_ancestors = directives.get("frame-ancestors")

    if "'unsafe-inline'" in script_src:
        findings.append(
            _finding(
                title="CSP permite scripts inline ('unsafe-inline')",
                severity="high",
                category="web-headers",
                description=(
                    "A Content-Security-Policy permite 'unsafe-inline' em "
                    "script-src/default-src — isso anula a principal proteção da "
                    "CSP contra XSS, já que o payload mais comum de XSS refletido/"
                    "armazenado é justamente um script inline."
                ),
                evidence=f"CSP: '{csp}' — script-src/default-src inclui 'unsafe-inline'.",
                recommendation=(
                    "Remover 'unsafe-inline'; usar nonces (`'nonce-<valor>'`, gerado "
                    "por requisição) ou hashes (`'sha256-<hash>'`) para scripts "
                    "legítimos inline, ou migrar para arquivos .js externos."
                ),
                playbook_key="misconfig.weak-csp",
            )
        )
    if "'unsafe-eval'" in script_src:
        findings.append(
            _finding(
                title="CSP permite 'unsafe-eval'",
                severity="medium",
                category="web-headers",
                description=(
                    "A CSP permite 'unsafe-eval' em script-src/default-src — "
                    "habilita `eval()`/`new Function()`, um vetor comum para "
                    "escalar um XSS que já conseguiu injetar dados em execução de código."
                ),
                evidence=f"CSP: '{csp}' — script-src/default-src inclui 'unsafe-eval'.",
                recommendation="Remover 'unsafe-eval'; refatorar o código que depende de eval()/new Function().",
                playbook_key="misconfig.weak-csp",
            )
        )
    if any(src in _CSP_WILDCARD_SOURCES for src in script_src):
        findings.append(
            _finding(
                title="CSP permite scripts de qualquer origem",
                severity="high",
                category="web-headers",
                description=(
                    "O script-src/default-src da CSP inclui um wildcard total "
                    "('*') ou um esquema inteiro (http:/https:/data:) como origem "
                    "permitida — equivale a não ter restrição de origem alguma "
                    "para scripts, tornando a CSP inútil contra XSS baseado em "
                    "origem externa."
                ),
                evidence=f"CSP: '{csp}' — script-src/default-src inclui origem wildcard.",
                recommendation=(
                    "Restringir script-src a uma allowlist explícita dos domínios "
                    "realmente usados (CDNs específicos, 'self'), nunca um "
                    "wildcard total ou de esquema."
                ),
                playbook_key="misconfig.weak-csp",
            )
        )
    if not object_src or "'none'" not in object_src:
        findings.append(
            _finding(
                title="CSP não restringe object-src",
                severity="low",
                category="web-headers",
                description=(
                    "A CSP não define object-src 'none' (nem via default-src) — "
                    "plugins legados (Flash/Java applets/Silverlight) embutidos "
                    "via <object>/<embed> continuam um vetor possível, mesmo "
                    "residual, em navegadores/ambientes mais antigos."
                ),
                evidence=f"CSP: '{csp}' — object-src ausente ou não restrito a 'none'.",
                recommendation="Adicionar object-src 'none' à CSP (quase nenhum site moderno precisa de plugins).",
                playbook_key="misconfig.weak-csp",
            )
        )
    if frame_ancestors is None:
        findings.append(
            _finding(
                title="CSP não define frame-ancestors",
                severity="medium",
                category="web-headers",
                description=(
                    "A CSP não define frame-ancestors — diferente das demais "
                    "diretivas, frame-ancestors **não** cai para default-src, "
                    "então sua ausência deixa a proteção contra clickjacking "
                    "dependendo só do X-Frame-Options (se presente)."
                ),
                evidence=f"CSP: '{csp}' — diretiva frame-ancestors não encontrada.",
                recommendation=(
                    "Adicionar frame-ancestors 'self' (ou 'none') à CSP — é o "
                    "mecanismo moderno de proteção contra clickjacking, e não "
                    "depende de suporte legado como X-Frame-Options."
                ),
                playbook_key="misconfig.weak-csp",
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


#: Recursos ``http://`` embutidos numa página (src/href absolutos inseguros).
_HTTP_SUBRESOURCE_RE = re.compile(r"""(?:src|href)\s*=\s*['"]http://[^'"]+['"]""", re.IGNORECASE)

#: Assinaturas fortes de página de erro/debug exposta (stack trace, debugger).
_DEBUG_MARKERS: tuple[tuple[str, str], ...] = (
    ("you're seeing this error because you have debug = true", "Django DEBUG=True"),
    ("traceback (most recent call last)", "Traceback Python"),
    ("werkzeug debugger", "Werkzeug interactive debugger"),
    ("django version", "Django debug page"),
    ("action controller: exception caught", "Rails exception"),
    ("server error in '/' application", "ASP.NET stack trace"),
    ("whoops, looks like something went wrong", "Laravel/Whoops debug page"),
    ("<b>fatal error</b>", "PHP fatal error exposto"),
    ("stack trace:", "Stack trace exposto"),
)


def analyze_mixed_content(url: str, body: str, *, is_https: bool) -> dict[str, Any] | None:
    """Detecta conteúdo misto: página HTTPS que carrega sub-recursos por http:// (category ``tls``)."""
    if not is_https:
        return None
    match = _HTTP_SUBRESOURCE_RE.search(body)
    if not match:
        return None
    return _finding(
        title="Conteúdo misto (mixed content) em página HTTPS",
        severity="medium",
        category="tls",
        description=(
            "A página é servida por HTTPS mas carrega sub-recursos via http:// "
            "inseguro — o tráfego desses recursos pode ser interceptado/alterado "
            "em trânsito, quebrando as garantias do HTTPS (falha criptográfica)."
        ),
        evidence=f"URL: {url} | Parâmetro: '' | Recurso inseguro: {match.group(0)[:120]}",
        recommendation=(
            "Servir todos os sub-recursos por HTTPS e adicionar "
            "'Content-Security-Policy: upgrade-insecure-requests'."
        ),
        playbook_key="crypto.mixed-content",
    )


def analyze_login_over_http(
    url: str, forms: list[dict[str, Any]], *, is_https: bool
) -> dict[str, Any] | None:
    """Detecta formulário de login servido/submetido sobre HTTP (category ``credential``)."""
    if is_https:
        return None
    if not any(is_login_form(form) for form in forms):
        return None
    return _finding(
        title="Formulário de login transmitido sobre HTTP (sem TLS)",
        severity="high",
        category="credential",
        description=(
            "Um formulário de autenticação (com campo de senha) é servido sobre "
            "HTTP sem TLS — as credenciais trafegam em texto claro e podem ser "
            "capturadas por qualquer intermediário da rede (falha criptográfica)."
        ),
        evidence=f"URL: {url} | Parâmetro: '' | Formulário com campo de senha em página HTTP.",
        recommendation=(
            "Servir toda a aplicação (especialmente login) por HTTPS, redirecionar "
            "HTTP→HTTPS e enviar HSTS."
        ),
        playbook_key="crypto.cleartext-credentials",
    )


def analyze_debug_mode(url: str, status_code: int, body: str) -> dict[str, Any] | None:
    """Detecta página de debug/stack trace exposta (category ``exposure``)."""
    lowered = body.lower()
    for marker, label in _DEBUG_MARKERS:
        if marker in lowered:
            return _finding(
                title="Modo debug / stack trace exposto",
                severity="high",
                category="exposure",
                description=(
                    "A aplicação expõe uma página de erro detalhada/debug em "
                    f"produção ({label}) — revela caminhos internos, versões, "
                    "trechos de código e às vezes segredos, além de facilitar a "
                    "exploração (má configuração de segurança)."
                ),
                evidence=(
                    f"URL: {url} | Parâmetro: '' | HTTP {status_code}; marcador de "
                    f"debug na resposta: '{label}'."
                ),
                recommendation=(
                    "Desabilitar o modo debug em produção (ex.: DEBUG=False no "
                    "Django), retornar páginas de erro genéricas e registrar o "
                    "detalhe apenas no log interno."
                ),
                playbook_key="misconfig.debug-mode",
            )
    return None


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
