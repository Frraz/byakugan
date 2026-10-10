"""Testes do detector de CSRF (A01) — puro, sem rede/banco."""

from __future__ import annotations

from apps.scans.web.csrf import detect_missing_csrf_token, has_csrf_token


def test_has_csrf_token_recognizes_common_field_names():
    assert has_csrf_token(["csrfmiddlewaretoken", "comment"]) is True
    assert has_csrf_token(["_token", "amount"]) is True
    assert has_csrf_token(["authenticity_token"]) is True
    assert has_csrf_token(["amount", "to_account"]) is False


def test_detect_missing_csrf_token_flags_post_form_without_token():
    form = {"action": "http://t/transfer", "method": "POST", "inputs": ["amount", "to"]}
    finding = detect_missing_csrf_token(form=form)
    assert finding is not None
    assert finding["playbook_key"] == "access-control.csrf"
    assert finding["severity"] == "high"
    assert finding["category"] == "access-control"


def test_detect_missing_csrf_token_ignores_form_with_token():
    form = {
        "action": "http://t/transfer",
        "method": "POST",
        "inputs": ["amount", "csrf_token"],
    }
    assert detect_missing_csrf_token(form=form) is None


def test_detect_missing_csrf_token_ignores_get_forms():
    form = {"action": "http://t/search", "method": "GET", "inputs": ["q"]}
    assert detect_missing_csrf_token(form=form) is None


def test_detect_missing_csrf_token_lowers_severity_with_samesite_strict():
    form = {"action": "http://t/transfer", "method": "POST", "inputs": ["amount"]}
    finding = detect_missing_csrf_token(form=form, session_cookie_samesite="Strict")
    assert finding is not None
    assert finding["severity"] == "medium"
