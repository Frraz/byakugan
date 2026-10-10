"""Testes da checagem de exposição de paths sensíveis (com baseline diffing)."""

from __future__ import annotations

from apps.scans.web.exposure import classify_exposure, classify_source_map

BASELINE_404 = {"baseline_status": 404, "baseline_body": "Not Found"}


def test_exposed_path_with_matching_signature():
    finding = classify_exposure(
        path="/.git/HEAD",
        signature="ref:",
        status_code=200,
        body="ref: refs/heads/main\n",
        **BASELINE_404,
    )
    assert finding is not None
    assert finding["category"] == "exposure"
    assert finding["severity"] == "high"


def test_path_without_expected_signature_is_not_flagged():
    finding = classify_exposure(
        path="/.git/HEAD",
        signature="ref:",
        status_code=200,
        body="<html>some unrelated 200 content</html>",
        **BASELINE_404,
    )
    assert finding is None


def test_path_with_no_signature_requirement_flags_on_200():
    finding = classify_exposure(
        path="/admin",
        signature=None,
        status_code=200,
        body="<html>Admin Login</html>",
        **BASELINE_404,
    )
    assert finding is not None


def test_error_statuses_never_flagged():
    for status in (401, 403, 404, 429, 500, 501, 502, 503):
        finding = classify_exposure(
            path="/admin", signature=None, status_code=status, body="", **BASELINE_404
        )
        assert finding is None, f"status {status} should not be flagged"


def test_soft_404_is_not_flagged():
    """Servidor que devolve 200 com a MESMA página de erro para tudo — sem sinal real."""
    generic_page = "<html>Generic homepage content, same as everything else on this site</html>"
    finding = classify_exposure(
        path="/.git/HEAD",
        signature="ref:",
        status_code=200,
        body=generic_page,
        baseline_status=200,
        baseline_body=generic_page,
    )
    assert finding is None


def test_similar_but_not_identical_length_still_treated_as_baseline():
    finding = classify_exposure(
        path="/.git/HEAD",
        signature=None,
        status_code=200,
        body="a" * 100,
        baseline_status=200,
        baseline_body="a" * 110,  # diferença de 10 bytes, dentro do threshold
    )
    assert finding is None


def test_significantly_different_from_baseline_is_flagged():
    finding = classify_exposure(
        path="/backup.zip",
        signature=None,
        status_code=200,
        body="PK\x03\x04" + "binary zip content" * 50,
        baseline_status=200,
        baseline_body="short 404 page",
    )
    assert finding is not None


def test_finding_is_rn008_complete():
    finding = classify_exposure(
        path="/.env", signature="=", status_code=200, body="DB_PASSWORD=secret", **BASELINE_404
    )
    assert finding["description"].strip()
    assert finding["evidence"].strip()
    assert finding["recommendation"].strip()
    assert "/.env" in finding["evidence"]


# --- Source map exposure -------------------------------------------------

SOURCE_MAP_BODY = '{"version":3,"sources":["app.jsx"],"names":[],"mappings":"AAAA","file":"app.js"}'


def test_source_map_exposed_when_body_has_valid_structure():
    finding = classify_source_map(
        script_url="https://t/static/app.js",
        status_code=200,
        body=SOURCE_MAP_BODY,
        **BASELINE_404,
    )
    assert finding is not None
    assert finding["playbook_key"] == "exposure.source-map"
    assert "app.js.map" in finding["evidence"]


def test_source_map_not_flagged_without_map_structure():
    assert (
        classify_source_map(
            script_url="https://t/static/app.js",
            status_code=200,
            body="<html>404 custom page</html>",
            **BASELINE_404,
        )
        is None
    )


def test_swagger_json_exposed_gets_api_docs_playbook():
    finding = classify_exposure(
        path="/swagger.json",
        signature='"swagger"',
        status_code=200,
        body='{"swagger": "2.0", "paths": {}}',
        **BASELINE_404,
    )
    assert finding is not None
    assert finding["playbook_key"] == "exposure.api-docs"


def test_v3_api_docs_exposed_gets_api_docs_playbook():
    finding = classify_exposure(
        path="/v3/api-docs",
        signature='"openapi"',
        status_code=200,
        body='{"openapi": "3.0.0", "paths": {}}',
        **BASELINE_404,
    )
    assert finding is not None
    assert finding["playbook_key"] == "exposure.api-docs"


def test_source_map_not_flagged_when_matches_baseline():
    finding = classify_source_map(
        script_url="https://t/static/app.js",
        status_code=404,
        body="Not Found",
        baseline_status=404,
        baseline_body="Not Found",
    )
    assert finding is None
