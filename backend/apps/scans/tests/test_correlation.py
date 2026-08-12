"""Testes do Correlation Engine (regras puras, sem banco de dados)."""

from __future__ import annotations

from apps.scans.correlation import (
    RISK_SCORE_CAP,
    compute_asset_risk,
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
    assert {"category": "tls", "severity": "medium", "count": 2} in cells
    assert {"category": "software", "severity": "high", "count": 1} in cells
    assert len(cells) == 2
