"""Bibliotecas JS de front-end e a menor versão sem vulnerabilidade conhecida.

Tabela conservadora (estilo retire.js reduzido) usada por
``web/integrity.analyze_vulnerable_js`` para sinalizar componentes de front-end
desatualizados (OWASP A06:2021 / A03:2025 — Software Supply Chain). Cada entrada
é ``lib → (menor_versão_segura, referência)``: versões abaixo da segura têm
CVEs/advisories públicos conhecidos.

Fonte da verdade de versões é intencionalmente pequena e auditável — não
substitui o CVE engine (NVD), complementa-o no front-end onde o fingerprint de
servidor não alcança.
"""

from __future__ import annotations

#: lib (minúsculo) → (menor versão segura como tupla, referência curta).
SAFE_MIN_VERSION: dict[str, tuple[tuple[int, ...], str]] = {
    "jquery": ((3, 5, 0), "XSS em jQuery < 3.5.0 (CVE-2020-11022/11023)"),
    "jquery-ui": ((1, 13, 0), "XSS em jQuery UI < 1.13.0"),
    "angular": ((1, 8, 0), "Múltiplos XSS/prototype pollution em AngularJS < 1.8.0"),
    "bootstrap": ((3, 4, 1), "XSS em data-* do Bootstrap < 3.4.1 / < 4.3.1"),
    "lodash": ((4, 17, 21), "Prototype pollution em lodash < 4.17.21 (CVE-2021-23337)"),
    "handlebars": ((4, 7, 7), "Prototype pollution/RCE em handlebars < 4.7.7"),
    "moment": ((2, 29, 2), "ReDoS/path traversal em moment < 2.29.2 (CVE-2022-24785)"),
    "dompurify": ((2, 4, 0), "Bypass de sanitização em DOMPurify < 2.4.0"),
    "vue": ((2, 6, 12), "XSS/ReDoS em Vue < 2.6.12"),
}

#: Regex-friendly: nomes de arquivo típicos ``<lib>-<versão>(.min).js``.
#: A extração de (lib, versão) fica em ``web/integrity.py``.
