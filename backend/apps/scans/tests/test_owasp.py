"""Testes da taxonomia OWASP e da matriz de cobertura (puro — sem banco)."""

from __future__ import annotations

from apps.scans.owasp import (
    CATEGORY_TO_OWASP,
    CLASS_TO_OWASP,
    OWASP_2021,
    OWASP_2025,
    adapter_coverage,
    resolve_owasp,
)
from apps.scans.owasp_coverage import compute_owasp_coverage


def test_both_editions_have_ten_categories():
    assert len(OWASP_2021) == 10
    assert len(OWASP_2025) == 10


def test_ssrf_diverges_between_editions():
    # SSRF é categoria própria em 2021 (A10) e absorvido por Broken Access
    # Control em 2025 (A01) — o valor de mapear as duas edições.
    assert resolve_owasp(playbook_key="injection.ssrf") == ("A10", "A01", "CWE-918")


def test_outdated_components_maps_to_supply_chain_in_2025():
    o21, o25, _ = resolve_owasp(category="software")
    assert (o21, o25) == ("A06", "A03")


def test_resolve_prefers_playbook_over_category():
    # crypto.cleartext-credentials (A02/A04) vence a categoria "credential" (A07).
    assert resolve_owasp(playbook_key="crypto.cleartext-credentials", category="credential") == (
        "A02",
        "A04",
        "CWE-319",
    )


def test_resolve_falls_back_to_category_then_empty():
    assert resolve_owasp(category="cookie")[:2] == ("A05", "A02")
    assert resolve_owasp(playbook_key="inexistente.xyz") == ("", "", "")
    assert resolve_owasp() == ("", "", "")


def test_every_mapped_code_exists_in_its_edition():
    for pk, (o21, o25, _) in CLASS_TO_OWASP.items():
        assert o21 in OWASP_2021, pk
        assert o25 in OWASP_2025, pk
    for cat, (o21, o25, _) in CATEGORY_TO_OWASP.items():
        assert o21 in OWASP_2021, cat
        assert o25 in OWASP_2025, cat


def test_web_scan_adapter_covers_the_expected_categories():
    c21, c25 = adapter_coverage("web-scan")
    assert {"A01", "A02", "A03", "A05", "A07", "A08", "A10"}.issubset(c21)
    assert {"A01", "A02", "A03", "A04", "A05", "A07", "A08"}.issubset(c25)


def test_coverage_matrix_shape_and_status():
    rows = [
        {"owasp_2021": "A03", "owasp_2025": "A05", "severity": "critical", "dedup_key": "k1"},
        {"owasp_2021": "A10", "owasp_2025": "A01", "severity": "high", "dedup_key": "k2"},
        {"owasp_2021": "A03", "owasp_2025": "A05", "severity": "low", "dedup_key": "triaged"},
    ]
    cov = compute_owasp_coverage(
        finding_rows=rows,
        adapters_run=["web-scan", "tls", "cve-lookup"],
        proven_playbook_keys={"injection.sqli-error"},
        excluded_dedup_keys={"triaged"},
    )
    assert len(cov["2021"]) == 10 and len(cov["2025"]) == 10

    a03 = next(r for r in cov["2021"] if r["code"] == "A03")
    assert a03["findings"] == 1  # o triado foi excluído
    assert a03["highest_severity"] == "critical"
    assert a03["proven"] and a03["status"] == "proven"

    # A04:2021 (Insecure Design) — não detectável remotamente ⇒ cobertura limitada.
    a04 = next(r for r in cov["2021"] if r["code"] == "A04")
    assert a04["limited_coverage"] and a04["status"] == "limited"


def test_coverage_summary_counts():
    cov = compute_owasp_coverage(finding_rows=[], adapters_run=["web-scan", "tls", "cve-lookup"])
    assert cov["summary"]["2021"]["found"] == 0
    assert cov["summary"]["2021"]["tested"] >= 8
    assert cov["summary"]["2021"]["total"] == 10
