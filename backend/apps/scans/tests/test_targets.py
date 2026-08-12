"""Testes da expansão de alvo (CIDR/lista → hosts individuais)."""

from __future__ import annotations

from apps.scans.targets import DEFAULT_MAX_HOSTS, expand_target


def test_single_host_returns_itself():
    assert expand_target("empresa.com") == ["empresa.com"]


def test_single_ip_returns_itself():
    assert expand_target("192.168.0.10") == ["192.168.0.10"]


def test_cidr_expands_to_usable_hosts():
    hosts = expand_target("192.168.10.0/30")
    # /30 → 2 hosts utilizáveis (RFC: exclui rede e broadcast).
    assert hosts == ["192.168.10.1", "192.168.10.2"]


def test_cidr_expansion_respects_max_hosts_cap():
    hosts = expand_target("10.0.0.0/24", {"max_hosts": 5})
    assert len(hosts) == 5


def test_cidr_expansion_respects_default_cap():
    hosts = expand_target("10.0.0.0/16")
    assert len(hosts) == DEFAULT_MAX_HOSTS


def test_comma_separated_list_expands():
    hosts = expand_target("web01.empresa.com, web02.empresa.com")
    assert hosts == ["web01.empresa.com", "web02.empresa.com"]


def test_newline_separated_list_expands():
    hosts = expand_target("web01.empresa.com\nweb02.empresa.com")
    assert hosts == ["web01.empresa.com", "web02.empresa.com"]


def test_invalid_host_in_list_is_dropped():
    hosts = expand_target("web01.empresa.com, not_a_valid_host!!")
    assert hosts == ["web01.empresa.com"]


def test_host_out_of_scope_is_dropped_fail_closed():
    hosts = expand_target("192.168.10.0/30", {"authorization_scope": "192.168.20.0/24"})
    assert hosts == []


def test_host_in_scope_is_kept():
    hosts = expand_target("192.168.10.0/30", {"authorization_scope": "192.168.10.0/24"})
    assert hosts == ["192.168.10.1", "192.168.10.2"]


def test_dedup_preserves_order():
    hosts = expand_target("a.empresa.com, a.empresa.com, b.empresa.com")
    assert hosts == ["a.empresa.com", "b.empresa.com"]
