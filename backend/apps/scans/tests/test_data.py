"""Testes dos módulos de dados estáticos (portas, probes UDP, credenciais)."""

from __future__ import annotations

from apps.scans.adapters import COMMON_DKIM_SELECTORS, DEFAULT_PORTS
from apps.scans.data.default_creds import HTTP_BASIC_CREDS
from apps.scans.data.ports import TOP_100, TOP_1000
from apps.scans.data.subdomains import COMMON_SUBDOMAINS
from apps.scans.data.udp_probes import UDP_PROBES, UDP_SERVICE_NAMES
from apps.scans.data.web_paths import SENSITIVE_PATHS


def test_top_100_is_larger_than_default_ports():
    assert len(TOP_100) > len(DEFAULT_PORTS)
    assert all(isinstance(port, int) for port in TOP_100)
    assert all(isinstance(name, str) and name for name in TOP_100.values())


def test_top_1000_is_a_superset_of_top_100():
    assert set(TOP_100).issubset(set(TOP_1000))
    assert len(TOP_1000) > len(TOP_100)


def test_top_1000_covers_full_well_known_range():
    assert set(range(1, 1025)).issubset(set(TOP_1000))


def test_top_1000_unnamed_ports_are_labeled_unknown():
    # Uma porta bem-conhecida sem nome específico em TOP_100/high-value.
    assert TOP_1000[1] == "unknown"


def test_udp_probes_and_service_names_share_the_same_ports():
    assert set(UDP_PROBES) == set(UDP_SERVICE_NAMES)
    assert len(UDP_PROBES) == 6  # dns, ntp, netbios-ns, snmp, isakmp, mdns


def test_udp_probes_are_nonempty_bytes():
    assert all(isinstance(payload, bytes) and len(payload) > 0 for payload in UDP_PROBES.values())


def test_http_basic_creds_shape():
    assert len(HTTP_BASIC_CREDS) >= 3
    assert all(isinstance(pair, tuple) and len(pair) == 2 for pair in HTTP_BASIC_CREDS)
    assert ("admin", "admin") in HTTP_BASIC_CREDS


def test_common_subdomains_shape():
    assert len(COMMON_SUBDOMAINS) >= 100
    assert all(isinstance(prefix, str) and prefix for prefix in COMMON_SUBDOMAINS)
    assert len(COMMON_SUBDOMAINS) == len(set(COMMON_SUBDOMAINS))  # sem duplicatas
    assert "www" in COMMON_SUBDOMAINS
    assert "mail" in COMMON_SUBDOMAINS


def test_common_dkim_selectors_shape():
    assert len(COMMON_DKIM_SELECTORS) >= 3
    assert all(isinstance(s, str) and s for s in COMMON_DKIM_SELECTORS)


def test_sensitive_paths_shape():
    assert len(SENSITIVE_PATHS) >= 20
    assert all(path.startswith("/") for path in SENSITIVE_PATHS)
    assert "/.git/HEAD" in SENSITIVE_PATHS
    assert "/.env" in SENSITIVE_PATHS
    # assinatura, quando presente, deve ser uma string não-vazia
    for signature in SENSITIVE_PATHS.values():
        assert signature is None or (isinstance(signature, str) and signature)
