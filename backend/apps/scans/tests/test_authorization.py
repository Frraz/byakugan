"""Testes do enforcement de escopo de autorização (RN007)."""

from __future__ import annotations

import pytest

from apps.scans.authorization import is_target_in_scope


@pytest.mark.parametrize(
    ("target", "scope"),
    [
        ("empresa.com", "empresa.com"),
        ("web01.empresa.com", "empresa.com"),
        ("192.168.0.10", "192.168.0.0/24"),
        ("10.0.0.5", "10.0.0.0/8, empresa.com"),
        ("192.168.1.0/25", "192.168.1.0/24"),
    ],
)
def test_target_in_scope(target, scope):
    assert is_target_in_scope(target, scope) is True


@pytest.mark.parametrize(
    ("target", "scope"),
    [
        ("evil.com", "empresa.com"),
        ("192.168.1.10", "192.168.0.0/24"),
        ("empresa.com.attacker.net", "empresa.com"),
        ("10.0.0.5", ""),
    ],
)
def test_rn007_target_out_of_scope_is_blocked(target, scope):
    assert is_target_in_scope(target, scope) is False
