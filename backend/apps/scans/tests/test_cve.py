"""Testes do mapeamento de respostas da NVD (regras puras, sem rede)."""

from __future__ import annotations

from apps.scans.cve import build_cpe_match, map_cve_item, severity_bucket

NVD_ITEM_V31 = {
    "cve": {
        "id": "CVE-2024-12345",
        "descriptions": [
            {"lang": "es", "value": "descrição em espanhol — deve ser ignorada"},
            {"lang": "en", "value": "Buffer overflow in example software."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "baseSeverity": "HIGH",
                    "cvssData": {
                        "baseScore": 7.5,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    },
                }
            ],
            "cvssMetricV2": [
                {"cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"}}
            ],
        },
        "references": [{"url": "https://example.com/advisory"}, {"url": None}],
    }
}


def test_map_cve_item_extracts_fields():
    mapped = map_cve_item(NVD_ITEM_V31)
    assert mapped is not None
    assert mapped["cve"] == "CVE-2024-12345"
    assert mapped["description"] == "Buffer overflow in example software."
    assert mapped["cvss_score"] == 7.5
    assert mapped["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert mapped["severity"] == "high"
    assert mapped["references"] == ["https://example.com/advisory"]


def test_map_cve_item_prefers_v31_over_v2():
    mapped = map_cve_item(NVD_ITEM_V31)
    assert mapped["cvss_score"] == 7.5  # não o 5.0 do v2


def test_map_cve_item_returns_none_without_id():
    assert map_cve_item({"cve": {}}) is None
    assert map_cve_item({}) is None


def test_map_cve_item_falls_back_to_v2_when_v31_absent():
    item = {
        "cve": {
            "id": "CVE-2020-0001",
            "descriptions": [],
            "metrics": {
                "cvssMetricV2": [
                    {"cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"}}
                ]
            },
            "references": [],
        }
    }
    mapped = map_cve_item(item)
    assert mapped["cvss_score"] == 5.0
    assert mapped["severity"] == "medium"  # derivado do score (sem baseSeverity no v2)


def test_map_cve_item_without_metrics_defaults_to_info():
    item = {"cve": {"id": "CVE-2000-0000", "descriptions": [], "metrics": {}, "references": []}}
    mapped = map_cve_item(item)
    assert mapped["cvss_score"] is None
    assert mapped["severity"] == "info"


def test_severity_bucket_prefers_nvd_label_over_score():
    assert severity_bucket(1.0, "CRITICAL") == "critical"


def test_severity_bucket_ignores_unknown_label():
    assert severity_bucket(8.5, "weird-label") == "high"


def test_severity_bucket_score_thresholds():
    assert severity_bucket(9.5) == "critical"
    assert severity_bucket(7.0) == "high"
    assert severity_bucket(4.0) == "medium"
    assert severity_bucket(0.1) == "low"
    assert severity_bucket(0.0) == "info"
    assert severity_bucket(None) == "info"


def test_build_cpe_match_formats_cpe23_with_wildcard_vendor():
    assert build_cpe_match("nginx", "1.24.0") == "cpe:2.3:a:*:nginx:1.24.0:*"


def test_build_cpe_match_lowercases_and_strips():
    assert build_cpe_match("  OpenSSH  ", "8.2P1") == "cpe:2.3:a:*:openssh:8.2p1:*"


def test_build_cpe_match_normalizes_spaces_and_reserved_chars():
    assert build_cpe_match("http server", "1.0") == "cpe:2.3:a:*:http_server:1.0:*"
    assert build_cpe_match("foo:bar", "1/0") == "cpe:2.3:a:*:foo_bar:1_0:*"
