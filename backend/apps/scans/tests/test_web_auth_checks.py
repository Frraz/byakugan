"""Testes dos detectores de Authentication Failures (A07) — puro, sem rede/banco."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from apps.scans.web.auth_checks import (
    analyze_jwt,
    decode_jwt_unverified,
    detect_missing_rate_limit,
    detect_user_enumeration,
    elevate_claims,
    find_jwt_candidates,
    find_weak_hs256_secret,
    forge_jwt,
    is_login_form,
    was_rate_limited,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_jwt(header: dict, payload: dict, secret: str | None = None) -> str:
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    if secret is None:
        return f"{header_b64}.{payload_b64}."
    signature = hmac.new(
        secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
    ).digest()
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


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


# --- JWT fraco (A07) ---------------------------------------------------------


def test_find_jwt_candidates_extracts_from_free_text():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 99999999999})
    text = f"Authorization: Bearer {token} some other text eyJshort.notreally"
    found = find_jwt_candidates(text)
    assert token in found


def test_decode_jwt_unverified_reads_header_and_payload():
    token = _make_jwt({"alg": "HS256"}, {"sub": "42", "exp": 1})
    decoded = decode_jwt_unverified(token)
    assert decoded == ({"alg": "HS256"}, {"sub": "42", "exp": 1})


def test_decode_jwt_unverified_rejects_malformed_token():
    assert decode_jwt_unverified("not-a-jwt") is None
    assert decode_jwt_unverified("a.b") is None


def test_analyze_jwt_flags_alg_none():
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin", "exp": 99999999999})
    finding = analyze_jwt(token)
    assert finding is not None
    assert finding["playbook_key"] == "auth.jwt-weak"
    assert finding["severity"] == "critical"
    assert "none" in finding["description"]


def test_find_weak_hs256_secret_matches_common_secret():
    token = _make_jwt({"alg": "HS256"}, {"sub": "1", "exp": 1}, secret="secret")
    assert find_weak_hs256_secret(token) == "secret"


def test_find_weak_hs256_secret_none_for_strong_secret():
    token = _make_jwt(
        {"alg": "HS256"}, {"sub": "1", "exp": 1}, secret="a-very-long-random-secret-xyz"
    )
    assert find_weak_hs256_secret(token) is None


def test_analyze_jwt_flags_weak_hs256_secret():
    token = _make_jwt({"alg": "HS256"}, {"sub": "1", "exp": 99999999999}, secret="password")
    finding = analyze_jwt(token)
    assert finding is not None
    assert finding["playbook_key"] == "auth.jwt-weak"
    assert finding["severity"] == "critical"
    assert "password" in finding["evidence"]


def test_analyze_jwt_flags_missing_exp_claim():
    token = _make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="a-very-long-random-secret-xyz")
    finding = analyze_jwt(token)
    assert finding is not None
    assert finding["playbook_key"] == "auth.jwt-weak"
    assert finding["severity"] == "medium"


def test_analyze_jwt_returns_none_for_healthy_token():
    token = _make_jwt(
        {"alg": "HS256"}, {"sub": "1", "exp": 99999999999}, secret="a-very-long-random-secret-xyz"
    )
    assert analyze_jwt(token) is None


def test_analyze_jwt_includes_source_url_in_evidence_for_forgeable_findings():
    token = _make_jwt({"alg": "none"}, {"sub": "1", "exp": 99999999999})
    finding = analyze_jwt(token, source_url="https://t/account")
    assert finding is not None
    assert finding["evidence"].startswith("URL: https://t/account | Parâmetro: '' | Token:")


def test_analyze_jwt_omits_url_prefix_without_source_url():
    token = _make_jwt({"alg": "none"}, {"sub": "1", "exp": 99999999999})
    finding = analyze_jwt(token)
    assert finding["evidence"].startswith("Token:")


def test_analyze_jwt_missing_exp_finding_has_no_url_prefix_even_with_source_url():
    # Claim 'exp' ausente não é forjável por este motor — não ganha
    # coordenadas de exploração mesmo quando source_url é informado.
    token = _make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="a-very-long-random-secret-xyz")
    finding = analyze_jwt(token, source_url="https://t/account")
    assert finding["evidence"].startswith("Token:")


# --- Forja de JWT (motor de exploração) ----------------------------------


def test_elevate_claims_flips_existing_privilege_claims_by_type():
    payload = {"sub": "1", "role": "user", "is_admin": False, "scopes": ["read"]}
    elevated, changed = elevate_claims(payload)
    assert elevated["role"] == "admin"
    assert elevated["is_admin"] is True
    assert elevated["scopes"] == ["admin"]
    assert elevated["sub"] == "1"  # claim sem relação com privilégio: intocada
    assert set(changed) == {"role", "is_admin", "scopes"}


def test_elevate_claims_no_op_when_no_privilege_claim_present():
    payload = {"sub": "1", "exp": 99999999999}
    elevated, changed = elevate_claims(payload)
    assert elevated == payload
    assert changed == []


def test_forge_jwt_alg_none_has_empty_signature_segment():
    token = forge_jwt({"alg": "HS256"}, {"sub": "admin"}, secret=None)
    header_b64, payload_b64, signature_b64 = token.split(".")
    assert signature_b64 == ""
    header, payload = decode_jwt_unverified(token)
    assert header["alg"] == "none"
    assert payload == {"sub": "admin"}


def test_forge_jwt_hs256_signature_matches_find_weak_hs256_secret():
    token = forge_jwt({"alg": "HS256"}, {"sub": "admin"}, secret="secret")
    assert find_weak_hs256_secret(token) == "secret"
