"""Testes dos detectores de Integrity Failures (A08) — puro, sem rede/banco."""

from __future__ import annotations

from apps.scans.web.integrity import analyze_sri, analyze_vulnerable_js, parse_version

_HTML = (
    '<script src="https://cdn.example.com/jquery-1.8.3.min.js"></script>'
    '<script src="/local/app.js"></script>'
    '<script src="https://cdn.example.com/safe.js" integrity="sha384-abc"></script>'
    '<link rel="stylesheet" href="https://cdn.example.com/style.css">'
)


def test_sri_flags_external_without_integrity_only():
    findings = analyze_sri(_HTML, base_url="https://site.com/")
    # jquery externo + css externo sem integrity; local e o com integrity ignorados.
    assert len(findings) == 2
    assert all(f["playbook_key"] == "integrity.missing-sri" for f in findings)


def test_sri_ignores_same_origin():
    html = '<script src="https://site.com/app.js"></script>'
    assert analyze_sri(html, base_url="https://site.com/") == []


def test_vulnerable_js_flags_outdated_version():
    findings = analyze_vulnerable_js(_HTML, base_url="https://site.com/")
    assert findings and "jquery" in findings[0]["title"].lower()
    assert findings[0]["playbook_key"] == "integrity.vulnerable-js"


def test_vulnerable_js_ignores_safe_version():
    html = '<script src="https://cdn/jquery-3.6.0.min.js"></script>'
    assert analyze_vulnerable_js(html, base_url="https://s/") == []


def test_parse_version():
    assert parse_version("1.8.3") == (1, 8, 3)
    assert parse_version("4.17") == (4, 17)


def test_malformed_html_never_raises():
    assert analyze_sri("<script src=", base_url="https://s/") == []
