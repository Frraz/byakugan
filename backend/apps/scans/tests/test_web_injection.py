"""Testes dos detectores de injeção (puro — respostas já obtidas, sem rede)."""

from __future__ import annotations

from apps.scans.web.injection import (
    CRLF_HEADER_NAME,
    CRLF_HEADER_VALUE,
    HOST_HEADER_MARKER,
    ProbeResponse,
    boolean_sqli_payloads,
    build_checks,
    build_injected_url,
    build_nosqli_injected_url,
    detect_boolean_ldap,
    detect_boolean_nosqli,
    detect_boolean_sqli,
    detect_host_header_reflection,
    detect_time_based,
    ldap_boolean_payloads,
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


def test_sqli_error_does_not_false_positive_when_signature_already_in_baseline():
    """Ex.: uma página de documentação/erro estático que sempre menciona uma
    mensagem de erro de banco não vira achado só porque reaparece após o payload."""
    check = _check("sqli-error")
    body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    assert check.run(ProbeResponse(200, {}, body), body) is None


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


def test_ssti_does_not_false_positive_when_49_already_in_baseline():
    """Disciplina de red team: '49' mundano no baseline (ex.: contador da
    página) não pode virar SSTI só porque também aparece na resposta injetada
    — sem essa comparação, QUALQUER página com 'Mostrando 49 resultados' (ou
    qualquer número 49 estático) seria um falso positivo garantido."""
    check = _check("ssti-dollar")
    baseline = "<html>Mostrando 49 resultados</html>"
    injected = "<html>Mostrando 49 resultados</html>"  # payload não teve efeito algum
    assert check.run(ProbeResponse(200, {}, injected), baseline) is None


def test_ssti_still_detects_when_49_absent_from_baseline():
    check = _check("ssti-dollar")
    baseline = "<html>Mostrando 12 resultados</html>"
    injected = "<html>Result: 49</html>"
    assert check.run(ProbeResponse(200, {}, injected), baseline) is not None


# --- Command injection ------------------------------------------------


def test_command_injection_detects_id_output():
    check = _check("command-injection")
    resp = ProbeResponse(200, {}, "uid=0(root) gid=0(root) groups=0(root)")
    assert check.run(resp) is not None


def test_command_injection_not_detected_in_clean_response():
    check = _check("command-injection")
    assert check.run(ProbeResponse(200, {}, "<html>Command not found</html>")) is None


def test_command_injection_does_not_false_positive_when_output_already_in_baseline():
    """Uma página que SEMPRE mostra 'uid=0(root) gid=0(root)' (ex.: uma
    doc/exemplo estático) não vira achado só porque o texto também aparece
    na resposta ao payload injetado."""
    check = _check("command-injection")
    body = "uid=0(root) gid=0(root) groups=0(root)"
    assert check.run(ProbeResponse(200, {}, body), body) is None


# --- SSRF ----------------------------------------------------------------


def test_ssrf_detects_cloud_metadata_markers():
    check = _check("ssrf")
    assert check.run(ProbeResponse(200, {}, "ami-id: ami-0abcd1234")) is not None
    assert check.run(ProbeResponse(200, {}, '{"instance-id": "i-0123"}')) is not None


def test_ssrf_not_detected_in_clean_response():
    check = _check("ssrf")
    assert check.run(ProbeResponse(200, {}, "<html>Normal page</html>")) is None


def test_ssrf_does_not_false_positive_when_marker_already_in_baseline():
    """'meta-data/' isolado é genérico o bastante pra aparecer num path não
    relacionado (ex.: uma API que documenta seu próprio endpoint
    '/meta-data/schema') — baseline idêntico não pode virar SSRF."""
    check = _check("ssrf")
    body = "see /meta-data/ for the schema reference"
    assert check.run(ProbeResponse(200, {}, body), body) is None


# --- CRLF Injection ----------------------------------------------------


def test_crlf_injection_detects_genuine_extra_header():
    check = _check("crlf")
    resp = ProbeResponse(200, {CRLF_HEADER_NAME: CRLF_HEADER_VALUE}, "<html>ok</html>")
    assert check.run(resp) is not None


def test_crlf_injection_case_insensitive_header_match():
    check = _check("crlf")
    resp = ProbeResponse(200, {"X-Byakugan-CRLF": "Injected"}, "<html>ok</html>")
    assert check.run(resp) is not None


def test_crlf_injection_not_detected_without_extra_header():
    check = _check("crlf")
    assert check.run(ProbeResponse(200, {}, "<html>ok</html>")) is None


def test_crlf_injection_ignores_unrelated_header_with_same_name_different_value():
    check = _check("crlf")
    resp = ProbeResponse(200, {CRLF_HEADER_NAME: "something-else"}, "<html>ok</html>")
    assert check.run(resp) is None


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


# --- Host Header Injection ----------------------------------------------


def test_detect_host_header_reflection_in_location():
    evidence = detect_host_header_reflection(
        status_code=302,
        headers={"Location": f"https://{HOST_HEADER_MARKER}/reset?token=abc"},
        body="",
    )
    assert evidence is not None and HOST_HEADER_MARKER in evidence


def test_detect_host_header_reflection_in_body():
    evidence = detect_host_header_reflection(
        status_code=200,
        headers={},
        body=f'<link rel="canonical" href="https://{HOST_HEADER_MARKER}/page">',
    )
    assert evidence is not None


def test_detect_host_header_reflection_none_when_not_reflected():
    assert (
        detect_host_header_reflection(status_code=200, headers={}, body="<html>normal page</html>")
        is None
    )


# --- NoSQL injection (booleana) -----------------------------------------


def test_build_nosqli_injected_url_renames_key():
    url = build_nosqli_injected_url("http://t/users?id=5&sort=asc", "id", "$ne", "x")
    assert "id%5B%24ne%5D=x" in url or "id[$ne]=x" in url
    assert "sort=asc" in url
    assert "id=5" not in url


def test_detect_boolean_nosqli_flags_conditional_pattern():
    baseline = "<html>user profile: alice</html>"
    bypass = "<html>user profile: alice</html>"  # $ne continuou casando o registro
    exact = "<html>Nothing matched this query at all, much longer empty-state page</html>"
    evidence = detect_boolean_nosqli(bypass_body=bypass, exact_body=exact, baseline_body=baseline)
    assert evidence is not None


def test_detect_boolean_nosqli_no_signal_when_both_match_baseline():
    baseline = "<html>user profile: alice</html>"
    assert (
        detect_boolean_nosqli(bypass_body=baseline, exact_body=baseline, baseline_body=baseline)
        is None
    )


def test_detect_boolean_nosqli_no_signal_when_both_differ():
    baseline = "<html>user profile: alice</html>"
    different = "<html>a completely different and much longer page than the baseline</html>"
    assert (
        detect_boolean_nosqli(bypass_body=different, exact_body=different, baseline_body=baseline)
        is None
    )


# --- LDAP injection (booleana) -------------------------------------------


def test_ldap_boolean_payloads_append_wildcard_and_filter_close():
    true_payload, false_payload = ldap_boolean_payloads("alice")
    assert true_payload == "alice*"
    assert false_payload == "alice)(uid=byaknoexist"


def test_detect_boolean_ldap_flags_conditional_pattern():
    baseline = "<html>user profile: alice</html>"
    true_body = "<html>user profile: alice</html>"  # wildcard continuou casando
    false_body = "<html>No entries matched this search filter at all, much longer</html>"
    evidence = detect_boolean_ldap(
        true_body=true_body, false_body=false_body, baseline_body=baseline
    )
    assert evidence is not None


def test_detect_boolean_ldap_no_signal_when_both_match_baseline():
    baseline = "<html>user profile: alice</html>"
    assert (
        detect_boolean_ldap(true_body=baseline, false_body=baseline, baseline_body=baseline) is None
    )


def test_detect_boolean_ldap_no_signal_when_both_differ():
    baseline = "<html>user profile: alice</html>"
    different = "<html>a completely different and much longer page than the baseline</html>"
    assert (
        detect_boolean_ldap(true_body=different, false_body=different, baseline_body=baseline)
        is None
    )
