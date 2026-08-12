"""Assinaturas de fingerprinting HTTP (Fase 2).

Regras puras (sem I/O) que traduzem headers e corpo de uma resposta HTTP num
conjunto de tecnologias identificadas. Manter aqui as assinaturas isola a
lógica de reconhecimento da coleta de rede (``adapters.py``) e a torna
facilmente testável.

Cada tecnologia é um dict com: ``category``, ``name``, ``version`` (opcional),
``source`` e ``evidence``. As categorias espelham ``assets.models.Technology``.
"""

from __future__ import annotations

import re
from typing import Any

# --- Header "Server" → servidor web (+ dica de SO entre parênteses) ---------

_SERVER_PRODUCTS = ("nginx", "apache", "microsoft-iis", "openresty", "litespeed", "caddy")

# Sistemas operacionais frequentemente anunciados no Server do Apache.
_OS_HINTS = ("ubuntu", "debian", "centos", "red hat", "win64", "win32", "unix", "fedora")


def _parse_product_version(token: str) -> tuple[str, str | None]:
    """Divide ``nginx/1.24.0`` em ``("nginx", "1.24.0")``."""
    if "/" in token:
        name, _, version = token.partition("/")
        return name.strip(), (version.strip() or None)
    return token.strip(), None


def _match_server_header(value: str) -> list[dict[str, Any]]:
    """Extrai servidor web e dica de SO do header ``Server``."""
    techs: list[dict[str, Any]] = []
    first_token = value.split()[0] if value.split() else value
    name, version = _parse_product_version(first_token)
    if name and name.lower() in _SERVER_PRODUCTS:
        pretty = "Microsoft-IIS" if name.lower() == "microsoft-iis" else name.lower()
        techs.append(
            {
                "category": "web-server",
                "name": pretty,
                "version": version,
                "source": "http-header",
                "evidence": f"Server: {value}",
                "confidence": "high",
            }
        )
    lowered = value.lower()
    for hint in _OS_HINTS:
        if hint in lowered:
            techs.append(
                {
                    "category": "os",
                    "name": hint.title(),
                    "version": None,
                    "source": "http-header",
                    "evidence": f"Server: {value}",
                    "confidence": "low",
                }
            )
            break
    return techs


# --- Header "X-Powered-By" → linguagem/framework ----------------------------

_POWERED_BY = {
    "php": ("language", "PHP"),
    "asp.net": ("framework", "ASP.NET"),
    "express": ("framework", "Express"),
    "servlet": ("framework", "Java Servlet"),
}


def _match_powered_by(value: str) -> list[dict[str, Any]]:
    """Interpreta o header ``X-Powered-By``."""
    lowered = value.lower()
    for key, (category, name) in _POWERED_BY.items():
        if key in lowered:
            _, version = _parse_product_version(value)
            return [
                {
                    "category": category,
                    "name": name,
                    "version": version,
                    "source": "http-header",
                    "evidence": f"X-Powered-By: {value}",
                    "confidence": "high",
                }
            ]
    return []


# --- Cookies de sessão → framework/linguagem --------------------------------

_COOKIE_SIGNATURES = {
    "csrftoken": ("framework", "Django"),
    "sessionid": ("framework", "Django"),
    "laravel_session": ("framework", "Laravel"),
    "ci_session": ("framework", "CodeIgniter"),
    "phpsessid": ("language", "PHP"),
    "jsessionid": ("language", "Java"),
    "asp.net_sessionid": ("framework", "ASP.NET"),
    "wordpress_logged_in": ("cms", "WordPress"),
}


def _match_cookies(set_cookie: str) -> list[dict[str, Any]]:
    """Reconhece frameworks/linguagens por nomes de cookie de sessão."""
    lowered = set_cookie.lower()
    techs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cookie, (category, name) in _COOKIE_SIGNATURES.items():
        if cookie in lowered and name not in seen:
            seen.add(name)
            techs.append(
                {
                    "category": category,
                    "name": name,
                    "version": None,
                    "source": "http-cookie",
                    "evidence": f"Set-Cookie contém {cookie}",
                    "confidence": "medium",
                }
            )
    return techs


# --- Corpo HTML → CMS/frontend ---------------------------------------------

_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_NG_VERSION_RE = re.compile(r'ng-version=["\']([^"\']+)["\']', re.IGNORECASE)

_BODY_SIGNATURES: list[tuple[str, tuple[str, str]]] = [
    ("wp-content", ("cms", "WordPress")),
    ("wp-includes", ("cms", "WordPress")),
    ("/sites/all/", ("cms", "Drupal")),
    ("drupal.settings", ("cms", "Drupal")),
    ("__next_data__", ("frontend", "Next.js")),
    ("data-reactroot", ("frontend", "React")),
    ("__nuxt__", ("frontend", "Nuxt.js")),
    ("vite/client", ("frontend", "Vite")),
]


def _match_body(body: str) -> list[dict[str, Any]]:
    """Reconhece CMS e tecnologias de frontend por padrões no HTML."""
    techs: list[dict[str, Any]] = []
    seen: set[str] = set()
    lowered = body.lower()

    ng = _NG_VERSION_RE.search(body)
    if ng:
        seen.add("Angular")
        techs.append(
            {
                "category": "frontend",
                "name": "Angular",
                "version": ng.group(1),
                "source": "html",
                "evidence": f'ng-version="{ng.group(1)}"',
                "confidence": "high",
            }
        )

    meta = _META_GENERATOR_RE.search(body)
    if meta:
        content = meta.group(1).strip()
        name, version = _parse_product_version(content.replace(" ", "/", 1))
        seen.add(name)
        techs.append(
            {
                "category": "cms",
                "name": name,
                "version": version,
                "source": "html",
                "evidence": f'meta generator: "{content}"',
                "confidence": "medium",
            }
        )

    for needle, (category, name) in _BODY_SIGNATURES:
        if needle in lowered and name not in seen:
            seen.add(name)
            techs.append(
                {
                    "category": category,
                    "name": name,
                    "version": None,
                    "source": "html",
                    "evidence": f"corpo contém '{needle}'",
                    "confidence": "medium",
                }
            )
    return techs


def fingerprint_http(headers: dict[str, str], body: str) -> list[dict[str, Any]]:
    """Aplica todas as assinaturas a uma resposta HTTP.

    Args:
        headers: Headers da resposta (case-insensitive por convenção do caller).
        body: Corpo textual da resposta (pode ser vazio).

    Returns:
        Lista de tecnologias identificadas, deduplicadas por (categoria, nome).
    """
    # Normaliza as chaves de header para lookup case-insensitive.
    lower = {k.lower(): v for k, v in headers.items()}

    techs: list[dict[str, Any]] = []
    if "server" in lower:
        techs.extend(_match_server_header(lower["server"]))
    if "x-powered-by" in lower:
        techs.extend(_match_powered_by(lower["x-powered-by"]))
    if "x-generator" in lower:
        name, version = _parse_product_version(lower["x-generator"].replace(" ", "/", 1))
        techs.append(
            {
                "category": "cms",
                "name": name,
                "version": version,
                "source": "http-header",
                "evidence": f"X-Generator: {lower['x-generator']}",
                "confidence": "medium",
            }
        )
    if "set-cookie" in lower:
        techs.extend(_match_cookies(lower["set-cookie"]))
    if body:
        techs.extend(_match_body(body))

    # Dedup por (categoria, nome) mantendo a primeira (maior confiança na ordem).
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for tech in techs:
        key = (tech["category"], tech["name"].lower())
        if key not in deduped:
            deduped[key] = tech
    return list(deduped.values())
