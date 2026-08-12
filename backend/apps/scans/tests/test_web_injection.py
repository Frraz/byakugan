"""Testes dos detectores de injeção (puro — respostas já obtidas, sem rede)."""

from __future__ import annotations

from apps.scans.web.injection import (
    ProbeResponse,
    boolean_sqli_payloads,
    build_checks,
    build_injected_url,
    detect_boolean_sqli,
    detect_time_based,
)


def _check(key: str):
    return next(c for c in build_checks("ab12cd34") if c.key == key)


# --- build_injected_url -------------------------------------------------


def test_build_injected_url_replaces_only_target_param():
    url = build_injected_url("http://x.com/search?q=test&page=2", "q", "'")
    assert "q=%27" in url
    assert "page=2" in url


def test_build_injected_url_adds_param_when_absent():
    url = build_injected_url("http://x.com/search", "q", "payload")
    assert "q=payload" in url


# --- XSS ------------------------------------------------------------


def test_xss_detects_unescaped_reflection():
    check = _check("xss")
    resp = ProbeResponse(200, {}, f"<html>You searched: {check.payload}</html>")
    assert check.run(resp) is not None


def test_xss_not_detected_when_html_escaped():
    check = _check("xss")
    escaped = check.payload.replace("<", "&lt;").replace(">", "&gt;")
    resp = ProbeResponse(200, {}, f"<html>You searched: {escaped}</html>")
    assert check.run(resp) is None


# --- SQLi error-based -----------------------------------------------------


def test_sqli_error_detects_common_db_error_signatures():
    check = _check("sqli-error")
    samples = [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        "Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result",
        "org.postgresql.util.PSQLException: ERROR: unterminated quoted string",
        "ORA-00933: SQL command not properly ended",
        "Unclosed quotation mark after the character string ''",
        "SQLSTATE[42000]: Syntax error or access violation",
        "System.Data.SQLite.SQLiteException: SQL logic error",
    ]
    for body in samples:
        assert check.run(ProbeResponse(200, {}, body)) is not None, body


def test_sqli_error_not_detected_in_clean_response():
    check = _check("sqli-error")
    assert check.run(ProbeResponse(200, {}, "<html>Normal page, id=49</html>")) is None


# --- Path traversal -----------------------------------------------------


def test_path_traversal_detects_passwd_content():
    check = _check("path-traversal")
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"
    assert check.run(ProbeResponse(200, {}, body)) is not None


def test_path_traversal_not_detected_in_clean_response():
    check = _check("path-traversal")
    assert check.run(ProbeResponse(200, {}, "<html>File not found</html>")) is None


# --- Open redirect --------------------------------------------------


def test_open_redirect_detects_location_pointing_to_probe_domain():
    check = _check("open-redirect")
    resp = ProbeResponse(302, {"Location": "//byakugan-redirect-probe.invalid/"}, "")
    assert check.run(resp) is not None


def test_open_redirect_not_flagged_for_relative_location():
    check = _check("open-redirect")
    resp = ProbeResponse(302, {"Location": "/dashboard"}, "")
    assert check.run(resp) is None


def test_open_redirect_requires_redirect_status():
    check = _check("open-redirect")
    resp = ProbeResponse(200, {"Location": "//byakugan-redirect-probe.invalid/"}, "")
    assert check.run(resp) is None


# --- SSTI -----------------------------------------------------------


def test_ssti_dollar_detects_evaluated_expression():
    check = _check("ssti-dollar")
    assert check.run(ProbeResponse(200, {}, "<html>Result: 49</html>")) is not None


def test_ssti_mustache_detects_evaluated_expression():
    check = _check("ssti-mustache")
    assert check.run(ProbeResponse(200, {}, "<html>Result: 49</html>")) is not None


def test_ssti_not_detected_when_expression_reflected_literally():
    check = _check("ssti-dollar")
    assert check.run(ProbeResponse(200, {}, "<html>Result: ${7*7}</html>")) is None


def test_ssti_does_not_false_positive_on_embedded_digits():
    """'149' contém '49' mas não é um resultado avaliado isoladamente."""
    check = _check("ssti-dollar")
    assert check.run(ProbeResponse(200, {}, "<html>Price: $149.00</html>")) is None


# --- Command injection ------------------------------------------------


def test_command_injection_detects_id_output():
    check = _check("command-injection")
    resp = ProbeResponse(200, {}, "uid=0(root) gid=0(root) groups=0(root)")
    assert check.run(resp) is not None


def test_command_injection_not_detected_in_clean_response():
    check = _check("command-injection")
    assert check.run(ProbeResponse(200, {}, "<html>Command not found</html>")) is None


# --- Todos os checks são RN008-completos -------------------------------


def test_all_single_request_checks_produce_rn008_complete_findings():
    for check in build_checks("token1234"):
        finding = check.to_finding(url="http://x/search?q=1", param="q", evidence="ev")
        assert finding["description"].strip()
        assert finding["evidence"].strip()
        assert finding["recommendation"].strip()
        assert finding["category"] == "injection"
        assert finding["severity"] in {"critical", "high", "medium", "low", "info"}


# --- SQLi booleana ---------------------------------------------------


def test_boolean_sqli_payloads_append_to_original_value():
    true_payload, false_payload = boolean_sqli_payloads("42")
    assert true_payload == "42' AND '1'='1"
    assert false_payload == "42' AND '1'='2"


def test_detect_boolean_sqli_finds_conditional_behavior():
    baseline = "<html>0 results</html>"
    evidence = detect_boolean_sqli(
        true_body=baseline,
        false_body="<html>500 Internal Server Error occurred while processing</html>",
        baseline_body=baseline,
    )
    assert evidence is not None


def test_detect_boolean_sqli_no_signal_when_responses_all_similar():
    baseline = "<html>0 results</html>"
    assert (
        detect_boolean_sqli(true_body=baseline, false_body=baseline, baseline_body=baseline) is None
    )


def test_detect_boolean_sqli_no_signal_when_true_also_differs():
    """Se a condição 'verdadeira' TAMBÉM difere do baseline, não é o padrão esperado."""
    baseline = "<html>0 results</html>"
    different = "<html>Something totally different and much longer than the baseline page</html>"
    assert (
        detect_boolean_sqli(true_body=different, false_body=different, baseline_body=baseline)
        is None
    )


# --- Time-based -------------------------------------------------------


def test_detect_time_based_flags_large_delay():
    assert detect_time_based(elapsed_seconds=6.0, baseline_elapsed_seconds=0.3) is True


def test_detect_time_based_ignores_small_delay():
    assert detect_time_based(elapsed_seconds=0.8, baseline_elapsed_seconds=0.3) is False


def test_detect_time_based_threshold_boundary():
    assert detect_time_based(elapsed_seconds=4.3, baseline_elapsed_seconds=0.3) is True
    assert detect_time_based(elapsed_seconds=4.29, baseline_elapsed_seconds=0.3) is False
