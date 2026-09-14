"""Testes dos detectores de Broken Access Control (A01) — puro, sem rede/banco."""

from __future__ import annotations

from apps.scans.web.access_control import (
    classify_forced_browsing,
    detect_idor,
    is_idor_candidate,
    next_id,
)


def test_forced_browsing_flags_admin_content_without_auth():
    finding = classify_forced_browsing(
        url="http://t/admin/",
        path="/admin/",
        status_code=200,
        body="Admin Dashboard — Users, Settings, logout",
        baseline_status=404,
        baseline_body="not found",
    )
    assert finding is not None
    assert finding["playbook_key"] == "access-control.forced-browsing"
    assert finding["severity"] == "high"  # marcadores de admin ⇒ alta confiança


def test_forced_browsing_ignores_login_wall():
    assert (
        classify_forced_browsing(
            url="http://t/admin/",
            path="/admin/",
            status_code=200,
            body="Please log in to continue",
            baseline_status=404,
            baseline_body="",
        )
        is None
    )


def test_forced_browsing_ignores_redirect_and_softlanding():
    assert (
        classify_forced_browsing(
            url="x", path="/admin/", status_code=302, body="", baseline_status=404, baseline_body=""
        )
        is None
    )
    # Servidor que responde 200 pra tudo (soft-404): corpo igual ao baseline.
    assert (
        classify_forced_browsing(
            url="x",
            path="/admin/",
            status_code=200,
            body="same body",
            baseline_status=200,
            baseline_body="same body",
        )
        is None
    )


def test_idor_candidate_and_next_id():
    assert is_idor_candidate("42") and not is_idor_candidate("abc")
    assert next_id("42") == "43"
    assert next_id("0") == "1"


def test_idor_detects_distinct_objects_similar_size():
    finding = detect_idor(
        url="http://t/p?id=1",
        param="id",
        original_value="1",
        original_status=200,
        original_body="X" * 400 + "user one",
        variant_value="2",
        variant_status=200,
        variant_body="X" * 400 + "user two",
    )
    assert finding is not None and finding["playbook_key"] == "access-control.idor"


def test_idor_ignores_small_or_identical_bodies():
    assert (
        detect_idor(
            url="x",
            param="id",
            original_value="1",
            original_status=200,
            original_body="short",
            variant_value="2",
            variant_status=200,
            variant_body="short2",
        )
        is None
    )
    body = "Y" * 300
    assert (
        detect_idor(
            url="x",
            param="id",
            original_value="1",
            original_status=200,
            original_body=body,
            variant_value="2",
            variant_status=200,
            variant_body=body,
        )
        is None
    )
