"""Testes de validação de alvo (RN001)."""

from __future__ import annotations

import pytest

from apps.scans.validators import InvalidTarget, classify_target


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.168.0.10", "ip"),
        ("2001:db8::1", "ip"),
        ("10.0.0.0/24", "cidr"),
        ("empresa.com", "domain"),
        ("web01.empresa.com", "domain"),
        ("localhost", "host"),
    ],
)
def test_classify_valid_targets(value, expected):
    assert classify_target(value) == expected


@pytest.mark.parametrize("value", ["", "   ", "not a host", "300.300.300.300/99", "-bad-.com"])
def test_rn001_rejects_invalid_targets(value):
    with pytest.raises(InvalidTarget):
        classify_target(value)
