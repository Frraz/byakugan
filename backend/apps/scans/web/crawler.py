"""Spider BFS same-origin para descoberta de URLs/formulários (Fase 4).

Usa ``requests`` + ``html.parser.HTMLParser`` (stdlib) — sem dependência de
parsing de HTML externa. Limitado por ``max_pages``/``max_depth`` e
espaçado por ``rate_delay`` entre requisições — não é um crawler de
propósito geral, é um mapeamento rápido e educado da superfície do alvo,
usado só para descobrir onde rodar as checagens seguintes (passive/exposure/
methods/injection). A extração de links/formulários (``extract_links_and_forms``)
é pura — testável sem rede, mesmo padrão de ``signatures.py``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

DEFAULT_TIMEOUT = 5.0
#: Limite de corpo lido por página — evita baixar arquivos enormes durante o crawl.
MAX_BODY_CHARS = 200_000
_IGNORED_LINK_SCHEMES = ("javascript:", "mailto:", "tel:", "data:")


class _LinkFormExtractor(HTMLParser):
    """Extrai ``<a href>`` e ``<form>`` (com inputs/select/textarea nomeados)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k.lower(): v for k, v in attrs if v is not None}
        if tag == "a" and attr_dict.get("href"):
            self.links.append(attr_dict["href"])
        elif tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": (attr_dict.get("method") or "get").upper(),
                "inputs": [],
            }
        elif tag in {"input", "select", "textarea"} and self._current_form is not None:
            name = attr_dict.get("name")
            if name and name not in self._current_form["inputs"]:
                self._current_form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def extract_links_and_forms(base_url: str, html: str) -> tuple[list[str], list[dict[str, Any]]]:
    """Extrai links absolutos e formulários (action absoluta) de uma página HTML.

    Args:
        base_url: URL da página (usada para resolver hrefs/actions relativos).
        html: Corpo HTML já obtido (esta função não faz I/O).

    Returns:
        ``(links, forms)`` — ``links`` é uma lista de URLs absolutas (exclui
        ``javascript:``/``mailto:``/``tel:``/``data:``); ``forms`` é uma
        lista de ``{"action", "method", "inputs"}``.
    """
    parser = _LinkFormExtractor()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001 — HTML malformado não deve derrubar o crawl
        pass

    links = [
        urljoin(base_url, href)
        for href in parser.links
        if not href.lower().startswith(_IGNORED_LINK_SCHEMES) and not href.startswith("#")
    ]
    forms = [
        {
            "action": urljoin(base_url, form["action"]) if form["action"] else base_url,
            "method": form["method"],
            "inputs": form["inputs"],
        }
        for form in parser.forms
    ]
    return links, forms


def is_same_origin(url: str, base_url: str) -> bool:
    """True se ``url`` tiver o mesmo esquema+host (porta incl.) que ``base_url``."""
    a, b = urlparse(url), urlparse(base_url)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def extract_query_params(url: str) -> list[str]:
    """Retorna os nomes (deduplicados, ordem preservada) dos parâmetros de query da URL."""
    return list(parse_qs(urlparse(url).query).keys())


@dataclass
class Page:
    """Uma página obtida durante o crawl."""

    url: str
    status_code: int
    headers: dict[str, str]
    body: str


@dataclass
class CrawlResult:
    """Resultado agregado do crawl: páginas visitadas e formulários encontrados."""

    pages: list[Page] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)


class Crawler:
    """Spider BFS same-origin. Rede isolada em ``_fetch`` (seam sobrescrito em testes).

    ``fetch``, quando informado, substitui a implementação padrão de
    ``_fetch`` — permite que ``adapters.WebScanAdapter`` injete o **mesmo**
    seam de rede que usa para todas as outras checagens (exposure/methods/
    injection), em vez de duplicar a lógica de GET em dois lugares. Mockar
    ``WebScanAdapter._fetch`` num teste passa a afetar o crawl também.
    Usado sem injeção (``fetch=None``), o ``Crawler`` continua funcionando
    de forma independente — é assim que ``tests/test_crawler.py`` o testa.
    """

    def __init__(
        self,
        *,
        max_pages: int = 40,
        max_depth: int = 3,
        rate_delay: float = 0.1,
        timeout: float = DEFAULT_TIMEOUT,
        fetch: Callable[[str], tuple[int, dict[str, str], str] | None] | None = None,
    ) -> None:
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.rate_delay = rate_delay
        self.timeout = timeout
        self._fetch_override = fetch

    def _fetch(self, url: str) -> tuple[int, dict[str, str], str] | None:
        """GET simples e educado. Retorna ``(status, headers, corpo)`` ou ``None``."""
        if self._fetch_override is not None:
            return self._fetch_override(url)

        import requests
        from requests.exceptions import RequestException

        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
                stream=True,
                headers={"User-Agent": "Byakugan-Scanner/0.1 (authorized assessment)"},
            )
            body = response.raw.read(MAX_BODY_CHARS, decode_content=True) or b""
            return (
                response.status_code,
                dict(response.headers),
                body.decode("utf-8", errors="ignore"),
            )
        except (RequestException, OSError):
            return None

    def crawl(self, start_url: str) -> CrawlResult:
        """Percorre o site em BFS a partir de ``start_url``, sem sair da origem."""
        result = CrawlResult()
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(start_url, 0)]

        while queue and len(result.pages) < self.max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > self.max_depth:
                continue
            visited.add(url)

            if len(visited) > 1 and self.rate_delay > 0:
                time.sleep(self.rate_delay)

            fetched = self._fetch(url)
            if fetched is None:
                continue
            status, headers, body = fetched
            result.pages.append(Page(url=url, status_code=status, headers=headers, body=body))

            content_type = headers.get("Content-Type", "text/html")
            if status >= 400 or "text/html" not in content_type:
                continue

            links, forms = extract_links_and_forms(url, body)
            result.forms.extend(forms)
            for link in links:
                clean_link = link.split("#")[0]
                if clean_link not in visited and is_same_origin(clean_link, start_url):
                    queue.append((clean_link, depth + 1))

        return result
