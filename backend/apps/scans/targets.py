"""Expansão de alvo em hosts individuais (CIDR e listas).

Vive no orquestrador (``tasks.run_scan``), não nos adapters — cada adapter
continua recebendo um único host por execução, simples e testável. Este
módulo é o único ponto que faz o fan-out de um alvo amplo (CIDR, lista de
IPs/hosts) e, por segurança, **revalida cada host resultante contra o
``authorization_scope`` (RN007, fail-closed)** antes de devolvê-lo — nenhum
host fora do escopo autorizado chega aos adapters, mesmo que a expansão de
um CIDR ultrapasse o que foi originalmente autorizado.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .authorization import is_target_in_scope
from .validators import InvalidTarget, classify_target

#: Máximo de hosts expandidos por padrão a partir de um alvo amplo (CIDR/lista).
#: Um /24 tem 254 hosts úteis; o cap evita que um /16 vire uma varredura de
#: 65 mil hosts sem um pedido explícito e mais alto via ``options``.
DEFAULT_MAX_HOSTS = 256

_LIST_SPLIT_RE = re.compile(r"[,\s;]+")


def _split_list(target: str) -> list[str]:
    """Divide um alvo em formato de lista (vírgula/espaço/linha) em tokens."""
    return [t for t in _LIST_SPLIT_RE.split(target.strip()) if t]


def expand_target(target: str, options: dict[str, Any] | None = None) -> list[str]:
    """Expande ``target`` em uma lista de hosts individuais para varredura.

    - CIDR (``10.0.0.0/24``) → hosts individuais da rede, via
      ``ipaddress.ip_network(...).hosts()``.
    - Lista (separada por vírgula/espaço/nova linha) → cada item.
    - Host/domínio/IP único → lista de um elemento (comportamento atual).

    Cada host resultante é revalidado com ``classify_target`` (RN001) e, se
    ``authorization_scope`` for informado em ``options``, com
    ``is_target_in_scope`` (RN007) — hosts inválidos ou fora do escopo são
    descartados silenciosamente (nunca chegam a um adapter). O resultado é
    limitado por ``options["max_hosts"]`` (padrão ``DEFAULT_MAX_HOSTS``) e
    deduplicado preservando a ordem.

    Args:
        target: Alvo bruto do scan (host, domínio, IP, CIDR ou lista).
        options: Opções normalizadas do scan (``max_hosts``,
            ``authorization_scope`` opcional para revalidação de escopo).

    Returns:
        Lista de hosts únicos, válidos e (quando aplicável) dentro do escopo.
    """
    options = options or {}
    max_hosts = int(options.get("max_hosts", DEFAULT_MAX_HOSTS))
    scope = options.get("authorization_scope")

    candidates = _raw_candidates(target, max_hosts)

    seen: set[str] = set()
    hosts: list[str] = []
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate or candidate in seen:
            continue
        try:
            classify_target(candidate)  # RN001
        except InvalidTarget:
            continue
        if scope is not None and not is_target_in_scope(candidate, scope):  # RN007
            continue
        seen.add(candidate)
        hosts.append(candidate)
        if len(hosts) >= max_hosts:
            break

    return hosts


def _raw_candidates(target: str, max_hosts: int) -> list[str]:
    """Gera os candidatos brutos (antes de validação/escopo/dedup)."""
    stripped = target.strip()

    if "/" in stripped:
        try:
            network = ipaddress.ip_network(stripped, strict=False)
        except ValueError:
            return _split_list(stripped)
        # Rede muito pequena (/31, /32, host único) → o próprio alvo.
        hosts_iter = network.hosts()
        return [str(ip) for ip, _ in zip(hosts_iter, range(max_hosts), strict=False)] or [stripped]

    if _LIST_SPLIT_RE.search(stripped):
        return _split_list(stripped)

    return [stripped]
