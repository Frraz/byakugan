"""Validação de alvos de scan (RN001).

Um alvo válido é um host, domínio, IP (v4/v6) ou rede CIDR bem-formado.
A validação também deriva o ``kind`` do alvo, usado pelo cadastro de Target.
"""

from __future__ import annotations

import ipaddress
import re

# Rótulo de hostname/domínio conforme RFC 1123 (sem sublinhado, sem espaços).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)" r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class InvalidTarget(ValueError):
    """Alvo malformado (não é host, domínio, IP ou CIDR válido)."""


def classify_target(value: str) -> str:
    """Classifica o alvo e retorna seu ``kind``.

    Args:
        value: Alvo informado (host, domínio, IP ou CIDR).

    Returns:
        ``"ip"``, ``"cidr"``, ``"domain"`` ou ``"host"``.

    Raises:
        InvalidTarget: Se o valor não corresponder a nenhum formato válido.
    """
    candidate = (value or "").strip()
    if not candidate:
        raise InvalidTarget("Alvo vazio.")

    if "/" in candidate:
        try:
            ipaddress.ip_network(candidate, strict=False)
            return "cidr"
        except ValueError as exc:
            raise InvalidTarget(f"CIDR inválido: {candidate}") from exc

    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass

    if _HOSTNAME_RE.match(candidate):
        # Heurística: presença de ponto sugere domínio; caso contrário, host.
        return "domain" if "." in candidate else "host"

    raise InvalidTarget("Alvo inválido: informe host, domínio, IP ou CIDR válido.")


def validate_target(value: str) -> str:
    """Valida o alvo (RN001) e devolve o valor normalizado (sem espaços).

    Raises:
        InvalidTarget: Se o alvo for malformado.
    """
    classify_target(value)
    return value.strip()
