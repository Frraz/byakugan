"""Testes de normalização de opções de scan (perfis de intensidade)."""

from __future__ import annotations

from apps.scans.profiles import HARD_CAPS, normalize_options


def test_defaults_to_normal_intensity_when_missing():
    options = normalize_options("discovery", None)
    assert options["intensity"] == "normal"
    assert options["port_set"] == "top100"


def test_unknown_intensity_falls_back_to_normal():
    options = normalize_options("discovery", {"intensity": "nuclear"})
    assert options["intensity"] == "normal"


def test_aggressive_intensity_changes_defaults():
    options = normalize_options("full", {"intensity": "aggressive"})
    assert options["intensity"] == "aggressive"
    assert options["port_set"] == "top1000"
    assert options["rate_delay"] == 0.0


def test_user_override_wins_over_intensity_default():
    options = normalize_options("discovery", {"intensity": "safe", "max_hosts": 10})
    assert options["max_hosts"] == 10


def test_hard_cap_clamps_excessive_user_value():
    options = normalize_options("discovery", {"max_hosts": 999999})
    assert options["max_hosts"] == HARD_CAPS["max_hosts"]


def test_hard_cap_applies_to_all_capped_keys():
    options = normalize_options(
        "discovery",
        {"max_hosts": 999999, "max_pages": 999999, "max_workers": 999999, "wordlist_size": 999999},
    )
    for key, cap in HARD_CAPS.items():
        assert options[key] == cap


def test_enabled_checks_none_by_default():
    options = normalize_options("full", None)
    assert options["enabled_checks"] is None


def test_enabled_checks_override_is_a_list():
    options = normalize_options("full", {"enabled_checks": ["dns", "port-discovery"]})
    assert options["enabled_checks"] == ["dns", "port-discovery"]
