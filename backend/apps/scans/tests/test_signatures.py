"""Testes das assinaturas de fingerprinting HTTP (regras puras, sem rede)."""

from __future__ import annotations

from apps.scans.signatures import fingerprint_http


def _find(techs, category, name):
    return next(
        (t for t in techs if t["category"] == category and t["name"].lower() == name.lower()),
        None,
    )


def test_server_header_detects_web_server_and_version():
    techs = fingerprint_http({"Server": "nginx/1.24.0"}, "")
    tech = _find(techs, "web-server", "nginx")
    assert tech is not None
    assert tech["version"] == "1.24.0"
    assert tech["confidence"] == "high"


def test_server_header_detects_os_hint():
    techs = fingerprint_http({"Server": "Apache/2.4.52 (Ubuntu)"}, "")
    assert _find(techs, "web-server", "apache") is not None
    assert _find(techs, "os", "Ubuntu") is not None


def test_powered_by_detects_language():
    techs = fingerprint_http({"X-Powered-By": "PHP/8.2.0"}, "")
    tech = _find(techs, "language", "PHP")
    assert tech is not None and tech["version"] == "8.2.0"


def test_cookie_detects_framework():
    techs = fingerprint_http({"Set-Cookie": "csrftoken=abc; sessionid=xyz"}, "")
    assert _find(techs, "framework", "Django") is not None


def test_body_detects_cms_and_frontend():
    body = '<link href="/wp-content/theme.css"><div ng-version="17.1.0"></div>'
    techs = fingerprint_http({}, body)
    assert _find(techs, "cms", "WordPress") is not None
    angular = _find(techs, "frontend", "Angular")
    assert angular is not None and angular["version"] == "17.1.0"


def test_meta_generator_is_parsed():
    body = '<meta name="generator" content="Joomla! 4.2">'
    techs = fingerprint_http({}, body)
    joomla = _find(techs, "cms", "Joomla!")
    assert joomla is not None


def test_results_are_deduplicated_by_category_and_name():
    body = "wp-content wp-includes"  # duas assinaturas do mesmo WordPress
    techs = fingerprint_http({"Server": "nginx/1.24.0"}, body)
    wp = [t for t in techs if t["name"] == "WordPress"]
    assert len(wp) == 1
