"""Detecção de Software & Data Integrity Failures (OWASP A08) — Fase B.

Duas checagens sobre o HTML já obtido (sem I/O adicional):

- **Missing Subresource Integrity (SRI)**: ``<script>``/``<link>`` que carregam
  recursos de outra origem (CDN de terceiro) sem o atributo ``integrity`` — se
  o CDN for comprometido, código arbitrário roda na aplicação (A08).
- **Bibliotecas JS desatimezadas**: versão de biblioteca de front-end abaixo da
  menor versão sem vulnerabilidade conhecida (``data/js_libraries.py``) —
  componente vulnerável/supply chain (A06:2021 / A03:2025).

Parsing com ``html.parser`` da stdlib (consistente com ``web/crawler.py``,
sem dependência de terceiros). Funções puras: recebem HTML + a origem base.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from ..data.js_libraries import SAFE_MIN_VERSION


def _finding(
    *,
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: str,
    recommendation: str,
    playbook_key: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "playbook_key": playbook_key,
    }


class _SubresourceParser(HTMLParser):
    """Coleta ``<script src>`` e ``<link rel=stylesheet href>`` com/sem integrity."""

    def __init__(self) -> None:
        super().__init__()
        #: cada item: ``{"tag", "url", "has_integrity", "crossorigin"}``.
        self.subresources: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.subresources.append(
                {
                    "tag": "script",
                    "url": a["src"],
                    "has_integrity": "integrity" in a,
                    "crossorigin": "crossorigin" in a,
                }
            )
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            self.subresources.append(
                {
                    "tag": "link",
                    "url": a["href"],
                    "has_integrity": "integrity" in a,
                    "crossorigin": "crossorigin" in a,
                }
            )


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.netloc else ""


def _is_external(resource_url: str, base_origin: str) -> bool:
    """True se o recurso vem de outra origem (ou de ``//`` protocol-relative)."""
    parts = urlsplit(resource_url)
    if not parts.netloc:
        return False  # caminho relativo — mesma origem
    return _origin(resource_url) != base_origin


def analyze_sri(html: str, *, base_url: str) -> list[dict[str, Any]]:
    """Reporta recursos externos (script/css) carregados sem SRI (category ``integrity``)."""
    parser = _SubresourceParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001 — HTML malformado nunca deve quebrar o scan
        return []
    base_origin = _origin(base_url)
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for res in parser.subresources:
        if res["has_integrity"] or not _is_external(res["url"], base_origin):
            continue
        if res["url"] in seen:
            continue
        seen.add(res["url"])
        findings.append(
            _finding(
                title=f"Recurso externo sem Subresource Integrity (SRI): {res['tag']}",
                severity="medium",
                category="integrity",
                description=(
                    "Um recurso de outra origem (CDN de terceiro) é carregado sem o "
                    "atributo 'integrity' (SRI). Se o CDN for comprometido ou "
                    "sequestrado, código/estilo arbitrário executa no contexto da "
                    "aplicação — falha de integridade de software (supply chain)."
                ),
                evidence=(
                    f"URL: {base_url} | Parâmetro: '' | <{res['tag']}> externo sem "
                    f"integrity: {res['url']}"
                ),
                recommendation=(
                    "Adicionar 'integrity' (hash SRI) e 'crossorigin=anonymous' a "
                    "todo script/CSS de terceiro, ou hospedar o recurso na própria "
                    "origem e fixar a versão."
                ),
                playbook_key="integrity.missing-sri",
            )
        )
    return findings


#: ``<lib>-<versão>`` em nomes de arquivo/URL (ex.: ``jquery-1.8.3.min.js``,
#: ``bootstrap.3.3.7.min.css``, ``lodash@4.17.10/lodash.js``).
_LIB_VERSION_RE = re.compile(
    r"(?P<lib>[a-z][a-z0-9\-]*?)[-.@/](?P<version>\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)


def parse_version(text: str) -> tuple[int, ...]:
    """Converte ``"1.8.3"`` em ``(1, 8, 3)`` para comparação."""
    return tuple(int(p) for p in text.split("."))


def _extract_lib_version(url: str) -> tuple[str, tuple[int, ...]] | None:
    """Extrai (lib conhecida, versão) de uma URL de script, ou ``None``."""
    filename = url.rsplit("/", 1)[-1] if "/" in url else url
    for candidate in (filename, url):
        for match in _LIB_VERSION_RE.finditer(candidate):
            lib = match.group("lib").lower()
            if lib in SAFE_MIN_VERSION:
                try:
                    return lib, parse_version(match.group("version"))
                except ValueError:
                    continue
    return None


def analyze_vulnerable_js(html: str, *, base_url: str) -> list[dict[str, Any]]:
    """Reporta bibliotecas JS/CSS com versão vulnerável conhecida (category ``integrity``)."""
    parser = _SubresourceParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        return []
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for res in parser.subresources:
        extracted = _extract_lib_version(res["url"])
        if not extracted:
            continue
        lib, version = extracted
        safe_min, reference = SAFE_MIN_VERSION[lib]
        if version >= safe_min:
            continue
        version_str = ".".join(str(p) for p in version)
        if (lib, version_str) in seen:
            continue
        seen.add((lib, version_str))
        findings.append(
            _finding(
                title=f"Biblioteca front-end desatualizada: {lib} {version_str}",
                severity="medium",
                category="integrity",
                description=(
                    f"A página carrega {lib} {version_str}, abaixo da menor versão "
                    f"sem vulnerabilidade conhecida ({'.'.join(map(str, safe_min))}). "
                    f"{reference}. Componente desatualizado/vulnerável."
                ),
                evidence=(
                    f"URL: {base_url} | Parâmetro: '' | {lib} {version_str} "
                    f"carregado de {res['url']}"
                ),
                recommendation=(
                    f"Atualizar {lib} para >= {'.'.join(map(str, safe_min))} e manter "
                    "um inventário de dependências de front-end (SCA/SBOM)."
                ),
                playbook_key="integrity.vulnerable-js",
            )
        )
    return findings
