"""Testes do Correlation Engine (regras puras, sem banco de dados)."""

from __future__ import annotations

from apps.scans.correlation import (
    RISK_SCORE_CAP,
    compute_asset_risk,
    compute_chains,
    compute_heatmap,
    compute_risk,
    risk_level,
)


def test_risk_level_bands_match_cvss_scaled_by_ten():
    assert risk_level(95) == "critical"
    assert risk_level(82) == "high"  # exemplo de docs/reporting.md
    assert risk_level(70) == "high"
    assert risk_level(50) == "medium"
    assert risk_level(40) == "medium"
    assert risk_level(10) == "low"
    assert risk_level(0) == "info"


def test_compute_risk_sums_cvss_when_available():
    rows = [{"severity": "high", "cvss": 7.5}, {"severity": "critical", "cvss": 9.8}]
    result = compute_risk(rows)
    assert result.risk_score == 17.3
    assert result.risk_level == "low"  # score agregado, não a severidade de um finding isolado
    assert result.findings == 2
    assert result.severity == {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0}


def test_compute_risk_falls_back_to_severity_score_without_cvss():
    rows = [{"severity": "medium", "cvss": None}]
    result = compute_risk(rows)
    assert result.risk_score == 5.5  # SEVERITY_FALLBACK_SCORE["medium"]


def test_compute_risk_caps_at_100():
    rows = [{"severity": "critical", "cvss": 9.8} for _ in range(20)]
    result = compute_risk(rows)
    assert result.risk_score == RISK_SCORE_CAP
    assert result.risk_level == "critical"


def test_compute_risk_empty_is_zero_info():
    result = compute_risk([])
    assert result.risk_score == 0
    assert result.risk_level == "info"
    assert result.findings == 0


def test_compute_asset_risk_groups_and_sorts_descending():
    rows = [
        {
            "asset_id": "asset-a",
            "asset__ip": "10.0.0.1",
            "asset__hostname": "low-risk",
            "asset__domain": None,
            "severity": "low",
            "cvss": 2.0,
        },
        {
            "asset_id": "asset-b",
            "asset__ip": "10.0.0.2",
            "asset__hostname": "high-risk",
            "asset__domain": None,
            "severity": "critical",
            "cvss": 9.8,
        },
    ]
    assessments = compute_asset_risk(rows)
    assert [a["asset"] for a in assessments] == ["asset-b", "asset-a"]
    assert assessments[0]["hostname"] == "high-risk"
    assert assessments[0]["risk_score"] > assessments[1]["risk_score"]


def test_compute_heatmap_aggregates_by_category_and_severity():
    rows = [
        {"category": "tls", "severity": "medium"},
        {"category": "tls", "severity": "medium"},
        {"category": "software", "severity": "high"},
    ]
    cells = compute_heatmap(rows)
    tls_cell = next(c for c in cells if c["category"] == "tls")
    software_cell = next(c for c in cells if c["category"] == "software")
    assert tls_cell["severity"] == "medium" and tls_cell["count"] == 2
    assert software_cell["severity"] == "high" and software_cell["count"] == 1
    assert len(cells) == 2


def test_compute_heatmap_includes_category_label():
    cells = compute_heatmap([{"category": "tls", "severity": "medium"}])
    assert cells[0]["category_label"] == "TLS"


def test_compute_heatmap_unknown_category_falls_back_to_raw_value():
    cells = compute_heatmap([{"category": "some-future-category", "severity": "low"}])
    assert cells[0]["category_label"] == "some-future-category"


# --- compute_chains (correlação purple team) --------------------------------


def test_compute_chains_detects_xss_plus_weak_csp_on_same_asset():
    rows = [
        {"asset_id": "a1", "asset__ip": "10.0.0.1", "playbook_key": "injection.xss"},
        {"asset_id": "a1", "asset__ip": "10.0.0.1", "playbook_key": "misconfig.weak-csp"},
    ]
    chains = compute_chains(rows)
    assert len(chains) == 1
    assert chains[0]["chain_key"] == "xss-unmitigated-by-csp"
    assert chains[0]["asset"] == "a1"
    assert chains[0]["severity"] == "critical"
    assert chains[0]["classes"] == ["injection.xss", "misconfig.weak-csp"]


def test_compute_chains_no_match_when_only_one_class_present():
    rows = [{"asset_id": "a1", "playbook_key": "injection.xss"}]
    assert compute_chains(rows) == []


def test_compute_chains_no_match_when_classes_span_different_assets():
    rows = [
        {"asset_id": "a1", "playbook_key": "injection.xss"},
        {"asset_id": "a2", "playbook_key": "misconfig.weak-csp"},
    ]
    assert compute_chains(rows) == []


def test_compute_chains_detects_multiple_chains_on_same_asset():
    rows = [
        {"asset_id": "a1", "playbook_key": "injection.xss"},
        {"asset_id": "a1", "playbook_key": "misconfig.weak-csp"},
        {"asset_id": "a1", "playbook_key": "credential.default"},
        {"asset_id": "a1", "playbook_key": "auth.no-rate-limit"},
    ]
    chains = compute_chains(rows)
    keys = {c["chain_key"] for c in chains}
    assert keys == {"xss-unmitigated-by-csp", "default-creds-no-rate-limit"}


def test_compute_chains_ignores_rows_without_playbook_key():
    rows = [
        {"asset_id": "a1", "playbook_key": ""},
        {"asset_id": "a1", "playbook_key": None},
    ]
    assert compute_chains(rows) == []


def test_compute_chains_excludes_triaged_findings():
    rows = [
        {"asset_id": "a1", "playbook_key": "injection.xss", "dedup_key": "k1"},
        {"asset_id": "a1", "playbook_key": "misconfig.weak-csp", "dedup_key": "k2"},
    ]
    # Sem exclusão: cadeia detectada.
    assert len(compute_chains(rows)) == 1
    # Com o XSS triado como falso-positivo, a cadeia não se forma mais.
    assert compute_chains(rows, excluded_dedup_keys={"k1"}) == []


def test_compute_chains_sorted_by_severity_then_asset():
    rows = [
        {"asset_id": "z-asset", "playbook_key": "injection.xss"},
        {"asset_id": "z-asset", "playbook_key": "misconfig.weak-csp"},
        {"asset_id": "a-asset", "playbook_key": "injection.xss"},
        {"asset_id": "a-asset", "playbook_key": "misconfig.weak-csp"},
    ]
    chains = compute_chains(rows)
    assert [c["asset"] for c in chains] == ["a-asset", "z-asset"]
