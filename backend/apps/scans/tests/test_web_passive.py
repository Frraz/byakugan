"""Testes das checagens passivas web: headers, cookies, CORS, directory listing."""

from __future__ import annotations

from apps.scans.web.passive import (
    analyze_cookies,
    analyze_cors,
    analyze_csp_quality,
    analyze_directory_listing,
    analyze_security_headers,
)

PROBE_ORIGIN = "https://byakugan-cors-probe.invalid"


# --- security headers --------------------------------------------------------


def test_all_headers_missing_over_https():
    findings = analyze_security_headers({}, is_https=True)
    titles = {f["title"] for f in findings}
    assert "Header de segurança ausente: Strict-Transport-Security" in titles
    assert len(findings) == 6


def test_hsts_not_required_over_plain_http():
    findings = analyze_security_headers({}, is_https=False)
    titles = {f["title"] for f in findings}
    assert "Header de segurança ausente: Strict-Transport-Security" not in titles
    assert len(findings) == 5


def test_all_headers_present_produces_no_findings():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    assert analyze_security_headers(headers, is_https=True) == []


def test_header_lookup_is_case_insensitive():
    headers = {"strict-transport-security": "max-age=1", "x-frame-options": "DENY"}
    findings = analyze_security_headers(headers, is_https=True)
    titles = {f["title"] for f in findings}
    assert "Header de segurança ausente: Strict-Transport-Security" not in titles
    assert "Header de segurança ausente: X-Frame-Options" not in titles


def test_all_findings_are_rn008_complete():
    findings = analyze_security_headers({}, is_https=True)
    for f in findings:
        assert f["description"].strip()
        assert f["evidence"].strip()
        assert f["recommendation"].strip()
        assert f["category"] == "web-headers"


# --- CSP quality ----------------------------------------------------------


def test_csp_empty_string_produces_no_findings():
    assert analyze_csp_quality("") == []


def test_csp_strong_produces_no_findings():
    csp = "default-src 'self'; object-src 'none'; frame-ancestors 'self'"
    assert analyze_csp_quality(csp) == []


def test_csp_unsafe_inline_flagged():
    csp = "script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self'"
    findings = analyze_csp_quality(csp)
    titles = {f["title"] for f in findings}
    assert any("unsafe-inline" in t for t in titles)


def test_csp_unsafe_eval_flagged():
    csp = "script-src 'self' 'unsafe-eval'; object-src 'none'; frame-ancestors 'self'"
    findings = analyze_csp_quality(csp)
    titles = {f["title"] for f in findings}
    assert any("unsafe-eval" in t for t in titles)


def test_csp_wildcard_script_src_flagged():
    csp = "script-src *; object-src 'none'; frame-ancestors 'self'"
    findings = analyze_csp_quality(csp)
    titles = {f["title"] for f in findings}
    assert any("qualquer origem" in t for t in titles)


def test_csp_scheme_wildcard_flagged():
    csp = "default-src https:; object-src 'none'; frame-ancestors 'self'"
    findings = analyze_csp_quality(csp)
    titles = {f["title"] for f in findings}
    assert any("qualquer origem" in t for t in titles)


def test_csp_missing_object_src_flagged():
    csp = "script-src 'self'; frame-ancestors 'self'"
    findings = analyze_csp_quality(csp)
    titles = {f["title"] for f in findings}
    assert any("object-src" in t for t in titles)


def test_csp_missing_frame_ancestors_flagged():
    csp = "script-src 'self'; object-src 'none'"
    findings = analyze_csp_quality(csp)
    titles = {f["title"] for f in findings}
    assert any("frame-ancestors" in t for t in titles)


def test_csp_default_src_fallback_used_for_script_and_object():
    # Sem script-src/object-src explícitos, ambos caem para default-src — uma
    # default-src com 'unsafe-inline' e sem 'none' deve acusar os dois problemas.
    csp = "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'"
    findings = analyze_csp_quality(csp)
    titles = {f["title"] for f in findings}
    assert any("unsafe-inline" in t for t in titles)
    assert any("object-src" in t for t in titles)


def test_csp_quality_findings_are_rn008_complete():
    csp = "script-src *"
    for f in analyze_csp_quality(csp):
        assert f["description"].strip()
        assert f["evidence"].strip()
        assert f["recommendation"].strip()
        assert f["category"] == "web-headers"
        assert f["playbook_key"] == "misconfig.weak-csp"


# --- cookies ------------------------------------------------------------


def test_cookie_missing_all_flags_over_https():
    cookies = [{"name": "sessionid", "secure": False, "httponly": False, "samesite": None}]
    findings = analyze_cookies(cookies, is_https=True)
    assert len(findings) == 1
    assert "Secure" in findings[0]["description"]
    assert "HttpOnly" in findings[0]["description"]
    assert "SameSite" in findings[0]["description"]
    assert findings[0]["category"] == "cookie"


def test_cookie_secure_not_required_over_http():
    cookies = [{"name": "sessionid", "secure": False, "httponly": True, "samesite": "Lax"}]
    assert analyze_cookies(cookies, is_https=False) == []


def test_cookie_with_all_flags_produces_no_finding():
    cookies = [{"name": "sessionid", "secure": True, "httponly": True, "samesite": "Strict"}]
    assert analyze_cookies(cookies, is_https=True) == []


def test_multiple_cookies_each_evaluated_independently():
    cookies = [
        {"name": "good", "secure": True, "httponly": True, "samesite": "Strict"},
        {"name": "bad", "secure": False, "httponly": False, "samesite": None},
    ]
    findings = analyze_cookies(cookies, is_https=True)
    assert len(findings) == 1
    assert "bad" in findings[0]["title"]


# --- CORS ------------------------------------------------------------


def test_cors_wildcard_with_credentials_is_high_severity():
    findings = analyze_cors(
        {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        probe_origin=PROBE_ORIGIN,
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["category"] == "cors"


def test_cors_reflects_probe_origin_with_credentials():
    findings = analyze_cors(
        {
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
        probe_origin=PROBE_ORIGIN,
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_cors_reflects_probe_origin_without_credentials_is_medium():
    findings = analyze_cors(
        {"Access-Control-Allow-Origin": PROBE_ORIGIN}, probe_origin=PROBE_ORIGIN
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


def test_cors_no_header_produces_no_finding():
    assert analyze_cors({}, probe_origin=PROBE_ORIGIN) == []


def test_cors_fixed_allowlist_not_flagged():
    """Uma origem fixa e diferente da nossa (não reflete o probe) = allowlist real."""
    findings = analyze_cors(
        {"Access-Control-Allow-Origin": "https://trusted-partner.com"}, probe_origin=PROBE_ORIGIN
    )
    assert findings == []


def test_cors_wildcard_without_credentials_not_flagged_by_this_rule():
    """'*' sozinho (sem credentials) não é a combinação perigosa testada aqui."""
    findings = analyze_cors({"Access-Control-Allow-Origin": "*"}, probe_origin=PROBE_ORIGIN)
    assert findings == []


# --- directory listing --------------------------------------------------


def test_directory_listing_detected():
    body = "<html><head><title>Index of /uploads</title></head><body></body></html>"
    finding = analyze_directory_listing("http://x/uploads/", body)
    assert finding is not None
    assert finding["category"] == "exposure"


def test_directory_listing_not_present():
    assert analyze_directory_listing("http://x/", "<html>Normal homepage</html>") is None
