"""Enforcement de escopo de autorização de alvos (RN007).

Antes de enfileirar um scan, o alvo é validado contra o ``authorization_scope``
registrado. Varredura fora do escopo é bloqueada e auditada. Ver
docs/scanning-engine.md → Política de Autorização de Alvos.
"""

from __future__ import annotations

import ipaddress


def _tokens(scope: str) -> list[str]:
    """Divide o escopo em tokens (separados por vírgula, espaço ou nova linha)."""
    raw = (scope or "").replace("\n", ",").replace(";", ",").replace(" ", ",")
    return [t.strip().lower() for t in raw.split(",") if t.strip()]


def _target_in_token(target: str, token: str) -> bool:
    """Verifica se ``target`` está contido no ``token`` do escopo."""
    target = target.strip().lower()
    if target == token:
        return True

    # Escopo por domínio: cobre o próprio domínio e seus subdomínios.
    if not _looks_like_ip_or_cidr(token):
        return target == token or target.endswith("." + token)

    # Escopo por IP/CIDR: verifica pertinência à rede.
    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    try:
        if "/" in target:
            candidate = ipaddress.ip_network(target, strict=False)
            return candidate.subnet_of(network)
        return ipaddress.ip_address(target) in network
    except ValueError:
        return False


def _looks_like_ip_or_cidr(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def is_target_in_scope(target: str, authorization_scope: str) -> bool:
    """Retorna ``True`` se o alvo estiver dentro do escopo autorizado (RN007).

    Um escopo vazio nunca autoriza nada (fail-closed).
    """
    tokens = _tokens(authorization_scope)
    if not tokens:
        return False
    return any(_target_in_token(target, token) for token in tokens)
