"""Testes do crawler web (extração de HTML pura + BFS com fetch injetado)."""

from __future__ import annotations

from apps.scans.web.crawler import (
    Crawler,
    extract_links_and_forms,
    extract_query_params,
    is_same_origin,
)

SAMPLE_HTML = """
<html><body>
<a href="/about">About</a>
<a href="/product?id=5&cat=shoes">Product</a>
<a href="https://external.com/x">External</a>
<a href="javascript:void(0)">JS link</a>
<a href="mailto:a@b.com">Email</a>
<a href="#section">Anchor</a>
<a href="/login#top">Login with fragment</a>
<form action="/search" method="GET">
  <input type="text" name="q">
  <input type="hidden" name="csrf" value="abc">
  <select name="category"><option>a</option></select>
</form>
<form action="/comment" method="post">
  <textarea name="body"></textarea>
  <input type="submit" value="Post">
</form>
<form>
  <input name="noaction">
</form>
</body></html>
"""


def test_extract_links_resolves_relative_and_filters_non_http_schemes():
    links, _ = extract_links_and_forms("https://empresa.com/home", SAMPLE_HTML)
    assert "https://empresa.com/about" in links
    assert "https://empresa.com/product?id=5&cat=shoes" in links
    assert "https://external.com/x" in links  # extraído; filtro de origem é externo
    assert not any(link.startswith("javascript:") for link in links)
    assert not any(link.startswith("mailto:") for link in links)
    assert not any(link == "#section" for link in links)
    assert "https://empresa.com/login#top" in links


def test_extract_forms_captures_action_method_and_named_inputs():
    _, forms = extract_links_and_forms("https://empresa.com/home", SAMPLE_HTML)
    assert len(forms) == 3

    search_form = next(f for f in forms if f["action"] == "https://empresa.com/search")
    assert search_form["method"] == "GET"
    assert set(search_form["inputs"]) == {"q", "csrf", "category"}

    comment_form = next(f for f in forms if f["action"] == "https://empresa.com/comment")
    assert comment_form["method"] == "POST"
    assert comment_form["inputs"] == ["body"]  # input submit sem name= não entra

    noaction_form = next(f for f in forms if "noaction" in f["inputs"])
    assert noaction_form["action"] == "https://empresa.com/home"


def test_extract_links_and_forms_survives_malformed_html():
    assert extract_links_and_forms("https://x.com/", "<html><a href='/a'<body>") == (
        ["https://x.com/a"],
        [],
    )


def test_is_same_origin():
    assert is_same_origin("https://empresa.com/x", "https://empresa.com/home") is True
    assert is_same_origin("https://external.com/x", "https://empresa.com/home") is False
    assert is_same_origin("http://empresa.com/x", "https://empresa.com/home") is False
    assert is_same_origin("https://empresa.com:8080/x", "https://empresa.com/home") is False


def test_extract_query_params():
    assert extract_query_params("https://empresa.com/product?id=5&cat=shoes") == ["id", "cat"]
    assert extract_query_params("https://empresa.com/about") == []


# --- Crawler (BFS) com fetch injetado ---------------------------------------


def _fake_site(pages: dict[str, tuple[int, dict, str]]):
    def fetch(url: str):
        return pages.get(url)

    return fetch


def test_crawler_bfs_visits_same_origin_links():
    pages = {
        "https://x.com/": (200, {"Content-Type": "text/html"}, '<a href="/about">A</a>'),
        "https://x.com/about": (200, {"Content-Type": "text/html"}, "<html>About</html>"),
    }
    crawler = Crawler(max_pages=10, fetch=_fake_site(pages))
    result = crawler.crawl("https://x.com/")

    urls = {p.url for p in result.pages}
    assert urls == {"https://x.com/", "https://x.com/about"}


def test_crawler_does_not_leave_origin():
    pages = {
        "https://x.com/": (
            200,
            {"Content-Type": "text/html"},
            '<a href="https://evil.com/x">Evil</a>',
        ),
    }
    crawler = Crawler(max_pages=10, fetch=_fake_site(pages))
    result = crawler.crawl("https://x.com/")

    assert {p.url for p in result.pages} == {"https://x.com/"}


def test_crawler_respects_max_pages():
    pages = {
        f"https://x.com/page{i}": (
            200,
            {"Content-Type": "text/html"},
            f'<a href="/page{i + 1}">next</a>',
        )
        for i in range(20)
    }
    pages["https://x.com/"] = (200, {"Content-Type": "text/html"}, '<a href="/page0">go</a>')
    # max_depth generoso: este teste mira max_pages, não a interação com depth
    # (a cadeia é linear, então cada página soma +1 de profundidade).
    crawler = Crawler(max_pages=5, max_depth=20, fetch=_fake_site(pages))
    result = crawler.crawl("https://x.com/")

    assert len(result.pages) == 5


def test_crawler_respects_max_depth():
    # cadeia linear: / -> /a -> /b -> /c ...
    pages = {
        "https://x.com/": (200, {"Content-Type": "text/html"}, '<a href="/a">a</a>'),
        "https://x.com/a": (200, {"Content-Type": "text/html"}, '<a href="/b">b</a>'),
        "https://x.com/b": (200, {"Content-Type": "text/html"}, '<a href="/c">c</a>'),
        "https://x.com/c": (200, {"Content-Type": "text/html"}, "<html>deep</html>"),
    }
    crawler = Crawler(max_pages=100, max_depth=1, fetch=_fake_site(pages))
    result = crawler.crawl("https://x.com/")

    urls = {p.url for p in result.pages}
    # depth 0: /, depth 1: /a — /b (depth 2) e além não são visitados.
    assert urls == {"https://x.com/", "https://x.com/a"}


def test_crawler_stops_following_links_on_non_html_content_type():
    pages = {
        "https://x.com/": (
            200,
            {"Content-Type": "application/pdf"},
            '<a href="/hidden">should not be followed</a>',
        ),
    }
    crawler = Crawler(max_pages=10, fetch=_fake_site(pages))
    result = crawler.crawl("https://x.com/")

    assert {p.url for p in result.pages} == {"https://x.com/"}


def test_crawler_does_not_follow_links_from_error_pages():
    pages = {
        "https://x.com/": (
            404,
            {"Content-Type": "text/html"},
            '<a href="/hidden">should not be followed</a>',
        ),
    }
    crawler = Crawler(max_pages=10, fetch=_fake_site(pages))
    result = crawler.crawl("https://x.com/")

    assert {p.url for p in result.pages} == {"https://x.com/"}


def test_crawler_handles_fetch_failure_gracefully():
    crawler = Crawler(max_pages=10, fetch=lambda url: None)
    result = crawler.crawl("https://x.com/")
    assert result.pages == []


def test_crawler_collects_forms_from_visited_pages():
    pages = {
        "https://x.com/": (
            200,
            {"Content-Type": "text/html"},
            '<form action="/search" method="GET"><input name="q"></form>',
        ),
    }
    crawler = Crawler(max_pages=10, fetch=_fake_site(pages))
    result = crawler.crawl("https://x.com/")

    assert len(result.forms) == 1
    assert result.forms[0]["action"] == "https://x.com/search"


def test_crawler_deduplicates_visited_urls():
    calls = []

    def counting_fetch(url):
        calls.append(url)
        if url == "https://x.com/":
            return 200, {"Content-Type": "text/html"}, '<a href="/a">a</a><a href="/a">a again</a>'
        return 200, {"Content-Type": "text/html"}, "<html>a</html>"

    crawler = Crawler(max_pages=10, fetch=counting_fetch)
    crawler.crawl("https://x.com/")

    assert calls.count("https://x.com/a") == 1
