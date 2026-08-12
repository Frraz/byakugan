"""Perfis/opções de scan: profundidade e limites por intensidade.

``Scan.scan_type`` continua sendo o seletor grosso do pipeline (discovery /
fingerprint / vulnerability / full); a profundidade de cada execução vem de
``Scan.options``, normalizado por ``normalize_options`` a partir da entrada
do usuário. Módulo puro — sem I/O, sem acesso a modelos.
"""

from __future__ import annotations

from typing import Any

#: Intensidades suportadas. ``aggressive`` habilita os checks mais invasivos
#: (credenciais default, time-based injection) — sempre não-destrutivos, mas
#: com maior chance de gerar ruído/carga no alvo.
INTENSITIES = ("safe", "normal", "aggressive")
DEFAULT_INTENSITY = "normal"

#: Limites-teto absolutos — nenhuma opção do usuário pode ultrapassá-los,
#: mesmo pedindo um valor maior. Protege contra varredura abusiva/DoS
#: acidental por um scan mal configurado.
HARD_CAPS: dict[str, int] = {
    "max_hosts": 1024,
    "max_pages": 200,
    "max_workers": 64,
    "wordlist_size": 5000,
}

#: Padrões por intensidade. ``port_set`` referencia listas em
#: ``apps.scans.data.ports`` (adicionadas na Fase 1); mantido como chave
#: simbólica aqui para não acoplar este módulo aos dados de portas.
_INTENSITY_DEFAULTS: dict[str, dict[str, Any]] = {
    "safe": {
        "port_set": "top16",
        "wordlist_size": 50,
        "max_hosts": 32,
        "max_pages": 10,
        "max_workers": 8,
        "rate_delay": 0.5,
        "enabled_checks": None,  # None = todos os checks do scan_type
    },
    "normal": {
        "port_set": "top100",
        "wordlist_size": 200,
        "max_hosts": 256,
        "max_pages": 40,
        "max_workers": 16,
        "rate_delay": 0.1,
        "enabled_checks": None,
    },
    "aggressive": {
        "port_set": "top1000",
        "wordlist_size": 1000,
        "max_hosts": 256,
        "max_pages": 100,
        "max_workers": 32,
        "rate_delay": 0.0,
        "enabled_checks": None,
    },
}


def profile_defaults(intensity: str) -> dict[str, Any]:
    """Retorna os padrões da intensidade informada (``normal`` se desconhecida)."""
    return dict(_INTENSITY_DEFAULTS.get(intensity, _INTENSITY_DEFAULTS[DEFAULT_INTENSITY]))


def normalize_options(scan_type: str, raw: dict[str, Any] | None) -> dict[str, Any]:
    """Mescla as opções do usuário sobre os padrões da intensidade e clampa os caps.

    Args:
        scan_type: ``Scan.ScanType`` do scan (não altera os padrões hoje, mas
            mantido no contrato para permitir ajuste fino por tipo no futuro).
        raw: Opções brutas informadas pelo cliente (``options`` do payload).

    Returns:
        Dict normalizado, sempre com ``intensity`` e todos os campos de
        ``profile_defaults``, com os limites numéricos nunca acima de
        ``HARD_CAPS``.
    """
    raw = dict(raw or {})
    intensity = raw.get("intensity") if raw.get("intensity") in INTENSITIES else DEFAULT_INTENSITY

    options = profile_defaults(intensity)
    options["intensity"] = intensity

    for key in ("port_set", "wordlist_size", "max_hosts", "max_pages", "max_workers", "rate_delay"):
        if key in raw and raw[key] is not None:
            options[key] = raw[key]

    if "enabled_checks" in raw and raw["enabled_checks"] is not None:
        options["enabled_checks"] = list(raw["enabled_checks"])

    for key, cap in HARD_CAPS.items():
        try:
            value = int(options[key])
        except (TypeError, ValueError):
            continue
        options[key] = max(0, min(value, cap))

    return options
