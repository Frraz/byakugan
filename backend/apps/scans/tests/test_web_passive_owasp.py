"""Testes das checagens passivas OWASP adicionais (A02/A05) — puro."""

from __future__ import annotations

from apps.scans.web.passive import (
    analyze_debug_mode,
    analyze_login_over_http,
    analyze_mixed_content,
)


def test_mixed_content_only_on_https():
    finding = analyze_mixed_content(
        "https://s/", "<img src='http://insecure/x.png'>", is_https=True
    )
    assert finding is not None and finding["playbook_key"] == "crypto.mixed-content"
    assert analyze_mixed_content("http://s/", "<img src='http://x'>", is_https=False) is None


def test_mixed_content_ignores_https_subresources():
    assert analyze_mixed_content("https://s/", "<img src='https://x/y.png'>", is_https=True) is None


def test_login_over_http_flagged_only_without_tls():
    forms = [{"method": "POST", "inputs": ["user", "password"]}]
    finding = analyze_login_over_http("http://s/login", forms, is_https=False)
    assert finding is not None and finding["playbook_key"] == "crypto.cleartext-credentials"
    assert analyze_login_over_http("https://s/", forms, is_https=True) is None
    assert (
        analyze_login_over_http("http://s/", [{"method": "GET", "inputs": ["q"]}], is_https=False)
        is None
    )


def test_debug_mode_detects_stack_trace():
    finding = analyze_debug_mode("http://s/", 500, "...\nTraceback (most recent call last):\n ...")
    assert finding is not None and finding["playbook_key"] == "misconfig.debug-mode"
    assert analyze_debug_mode("http://s/", 200, "normal homepage") is None


def test_debug_mode_detects_django_marker():
    body = "You're seeing this error because you have DEBUG = True in your settings"
    assert analyze_debug_mode("http://s/", 500, body) is not None
