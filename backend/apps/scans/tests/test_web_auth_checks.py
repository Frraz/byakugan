"""Testes dos detectores de Authentication Failures (A07) — puro, sem rede/banco."""

from __future__ import annotations

from apps.scans.web.auth_checks import (
    detect_missing_rate_limit,
    detect_user_enumeration,
    is_login_form,
    was_rate_limited,
)


def test_is_login_form_detects_password_field():
    assert is_login_form({"inputs": ["user", "password"]})
    assert is_login_form({"inputs": ["email", "senha"]})
    assert not is_login_form({"inputs": ["q", "sort"]})


def test_user_enumeration_flags_revealing_message():
    finding = detect_user_enumeration(url="http://t/login", body="Error: username not found")
    assert finding is not None
    assert finding["playbook_key"] == "auth.user-enumeration"


def test_user_enumeration_ignores_generic_message():
    assert detect_user_enumeration(url="x", body="Invalid credentials") is None


def test_user_enumeration_portuguese():
    assert detect_user_enumeration(url="x", body="Usuário não encontrado no sistema") is not None


def test_was_rate_limited_by_status_and_body():
    assert was_rate_limited(status_code=429, body="")
    assert was_rate_limited(status_code=200, body="Too many attempts, try again later")
    assert not was_rate_limited(status_code=200, body="Invalid credentials")


def test_missing_rate_limit_when_never_blocked():
    attempts = [(200, "bad"), (200, "bad"), (200, "bad"), (401, "bad")]
    finding = detect_missing_rate_limit(url="http://t/login", attempts=attempts)
    assert finding is not None and finding["playbook_key"] == "auth.no-rate-limit"


def test_missing_rate_limit_not_flagged_when_blocked_or_too_few():
    assert detect_missing_rate_limit(url="x", attempts=[(200, "bad"), (429, "")]) is None
    assert detect_missing_rate_limit(url="x", attempts=[(200, "bad")]) is None
