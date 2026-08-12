"""Testes da checagem de métodos HTTP perigosos (Allow/TRACE)."""

from __future__ import annotations

from apps.scans.web.methods import analyze_allow_header, analyze_trace_response


def test_dangerous_methods_flagged():
    findings = analyze_allow_header("http://x/api", "GET, POST, PUT, DELETE, OPTIONS")
    assert len(findings) == 1
    assert "PUT" in findings[0]["evidence"]
    assert "DELETE" in findings[0]["evidence"]
    assert findings[0]["category"] == "http-method"


def test_safe_methods_not_flagged():
    assert analyze_allow_header("http://x/api", "GET, POST, OPTIONS, HEAD") == []


def test_no_allow_header_produces_no_finding():
    assert analyze_allow_header("http://x/api", None) == []
    assert analyze_allow_header("http://x/api", "") == []


def test_allow_header_is_case_insensitive_and_whitespace_tolerant():
    findings = analyze_allow_header("http://x/api", " get,  trace ,options")
    assert len(findings) == 1
    assert "TRACE" in findings[0]["title"]  # normalizado (maiúsculo) no título
    assert "trace" in findings[0]["evidence"]  # evidência preserva o header cru


def test_trace_response_echoing_marker_is_flagged():
    finding = analyze_trace_response(
        "http://x/",
        status_code=200,
        body="TRACE / HTTP/1.1\r\nX-Probe: bykmarker123",
        probe_marker="bykmarker123",
    )
    assert finding is not None
    assert finding["category"] == "http-method"


def test_trace_not_200_is_not_flagged():
    finding = analyze_trace_response(
        "http://x/", status_code=405, body="Method Not Allowed", probe_marker="bykmarker123"
    )
    assert finding is None


def test_trace_200_without_marker_is_not_flagged():
    """TRACE pode retornar 200 por outro motivo (ex.: catch-all) sem de fato ecoar."""
    finding = analyze_trace_response(
        "http://x/",
        status_code=200,
        body="<html>unrelated content</html>",
        probe_marker="bykmarker123",
    )
    assert finding is None
