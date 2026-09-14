"""Taxonomia OWASP Top 10 (edições 2021 e 2025) — fonte única da verdade.

Transforma a classificação OWASP de "links soltos em playbooks" em uma
classificação de primeira classe, consultável e relatável. Cada finding é
mapeado para uma categoria de **cada** edição (2021 e 2025) e para um CWE
primário, a partir da sua ``playbook_key`` (preferencial) ou, como fallback,
da sua ``FindingCategory``.

Duas edições porque elas divergem de forma relevante: em 2025 o SSRF foi
absorvido por Broken Access Control (A01), Security Misconfiguration subiu
para A02, e surgiram A03 (Software Supply Chain Failures) e A10 (Mishandling
of Exceptional Conditions). Mapear as duas deixa o Byakugan defensável tanto
com material consolidado (2021) quanto com a edição mais atual (2025).

Referências:
- https://owasp.org/www-project-top-ten/ (2021)
- https://owasp.org/Top10/2025/
"""

from __future__ import annotations

#: OWASP Top 10 2021 — código → rótulo oficial (inglês).
OWASP_2021: dict[str, str] = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery (SSRF)",
}

#: OWASP Top 10 2025 — código → rótulo oficial (inglês).
OWASP_2025: dict[str, str] = {
    "A01": "A01:2025 - Broken Access Control",
    "A02": "A02:2025 - Security Misconfiguration",
    "A03": "A03:2025 - Software Supply Chain Failures",
    "A04": "A04:2025 - Cryptographic Failures",
    "A05": "A05:2025 - Injection",
    "A06": "A06:2025 - Insecure Design",
    "A07": "A07:2025 - Authentication Failures",
    "A08": "A08:2025 - Software or Data Integrity Failures",
    "A09": "A09:2025 - Logging & Alerting Failures",
    "A10": "A10:2025 - Mishandling of Exceptional Conditions",
}

#: Categorias que hoje **não** são detectáveis remotamente de forma confiável
#: (exigem revisão de design/código ou acesso a logs internos). A matriz de
#: cobertura as marca como "cobertura limitada" em vez de fingir cobertura —
#: honestidade técnica. Chave = (edição, código).
LIMITED_COVERAGE: frozenset[tuple[str, str]] = frozenset(
    {
        ("2021", "A04"),  # Insecure Design
        ("2021", "A09"),  # Security Logging and Monitoring Failures
        ("2025", "A06"),  # Insecure Design
        ("2025", "A09"),  # Logging & Alerting Failures
        ("2025", "A10"),  # Mishandling of Exceptional Conditions
    }
)


#: Mapa ``playbook_key`` → (código 2021, código 2025, CWE primário).
#: Fonte primária de classificação de um finding — mais específica que a
#: categoria. Cobre todos os ``playbook_key`` semeados
#: (``migrations/0006_seed_playbooks.py``) e as classes novas (Fase B/C).
CLASS_TO_OWASP: dict[str, tuple[str, str, str]] = {
    # --- Injection (A03:2021 → A05:2025) ---
    "injection.sqli-error": ("A03", "A05", "CWE-89"),
    "injection.sqli-boolean": ("A03", "A05", "CWE-89"),
    "injection.command-injection": ("A03", "A05", "CWE-78"),
    "injection.ssti": ("A03", "A05", "CWE-1336"),
    "injection.xss": ("A03", "A05", "CWE-79"),
    # Path traversal e open redirect: CWE-22/CWE-601 mapeiam para Broken Access
    # Control (A01) nas duas edições, conforme o mapeamento CWE→OWASP oficial.
    "injection.path-traversal": ("A01", "A01", "CWE-22"),
    "injection.open-redirect": ("A01", "A01", "CWE-601"),
    # SSRF: A10 em 2021 (categoria própria) → A01 em 2025 (absorvido).
    "injection.ssrf": ("A10", "A01", "CWE-918"),
    # --- Credenciais / autenticação (A07 nas duas edições) ---
    "credential.default": ("A07", "A07", "CWE-1392"),
    # --- Exposição / má-configuração (A05:2021 → A02:2025) ---
    "exposure.git": ("A05", "A02", "CWE-527"),
    "exposure.env": ("A05", "A02", "CWE-312"),
    "exposure.actuator": ("A05", "A02", "CWE-200"),
    "cors.misconfig": ("A05", "A02", "CWE-942"),
    "dns.zone-transfer": ("A05", "A02", "CWE-200"),
    "subdomain.takeover": ("A05", "A02", "CWE-350"),
    # --- Broken Access Control (A01 nas duas edições) — Fase B/C ---
    "access-control.forced-browsing": ("A01", "A01", "CWE-425"),
    "access-control.idor": ("A01", "A01", "CWE-639"),
    # --- Identification & Authentication Failures (A07) — Fase B/C ---
    "auth.user-enumeration": ("A07", "A07", "CWE-204"),
    "auth.weak-session": ("A07", "A07", "CWE-614"),
    "auth.no-rate-limit": ("A07", "A07", "CWE-307"),
    # --- Cryptographic Failures (A02:2021 → A04:2025) — Fase B ---
    "crypto.cleartext-credentials": ("A02", "A04", "CWE-319"),
    "crypto.mixed-content": ("A02", "A04", "CWE-319"),
    "crypto.sensitive-data-in-url": ("A02", "A04", "CWE-598"),
    # --- Software & Data Integrity Failures (A08 nas duas edições) — Fase B ---
    "integrity.missing-sri": ("A08", "A08", "CWE-353"),
    # Componentes desatualizados: A06:2021 → A03:2025 (Software Supply Chain).
    "integrity.vulnerable-js": ("A06", "A03", "CWE-1104"),
    # --- Security Misconfiguration extra (A05:2021 → A02:2025) — Fase B ---
    "misconfig.debug-mode": ("A05", "A02", "CWE-489"),
    "misconfig.default-page": ("A05", "A02", "CWE-1188"),
    "misconfig.verbose-error": ("A05", "A02", "CWE-209"),
}


#: Fallback por ``FindingCategory`` (findings sem ``playbook_key``). Menos
#: preciso que ``CLASS_TO_OWASP``, mas garante que todo finding receba alguma
#: classificação OWASP.
CATEGORY_TO_OWASP: dict[str, tuple[str, str, str]] = {
    "software": ("A06", "A03", ""),  # Vulnerable/Outdated → Supply Chain
    "service": ("A05", "A02", ""),
    "network": ("A05", "A02", ""),
    "credential": ("A07", "A07", ""),
    "tls": ("A02", "A04", "CWE-327"),
    "certificate": ("A02", "A04", "CWE-295"),
    "dns": ("A05", "A02", ""),
    "email-security": ("A05", "A02", ""),
    "subdomain": ("A05", "A02", ""),
    "web-headers": ("A05", "A02", "CWE-693"),
    "cookie": ("A05", "A02", "CWE-614"),
    "cors": ("A05", "A02", "CWE-942"),
    "exposure": ("A05", "A02", "CWE-200"),
    "http-method": ("A05", "A02", "CWE-650"),
    "injection": ("A03", "A05", ""),
    # Categorias novas (Fase B) — quando o finding não trouxer playbook_key.
    "access-control": ("A01", "A01", "CWE-284"),
    "auth": ("A07", "A07", ""),
    "integrity": ("A08", "A08", ""),
}


def resolve_owasp(playbook_key: str = "", category: str = "") -> tuple[str, str, str]:
    """Resolve (código 2021, código 2025, CWE) de um finding.

    Prioriza ``playbook_key`` (classe específica) e cai para ``category``
    quando não houver classe mapeada. Retorna ``("", "", "")`` quando nada
    casa — o finding fica sem classificação OWASP (retrocompatível com linhas
    antigas), nunca levanta erro. Função pura, reutilizada por
    ``parsers.persist_findings`` e pela migration de backfill.
    """
    if playbook_key and playbook_key in CLASS_TO_OWASP:
        return CLASS_TO_OWASP[playbook_key]
    if category and category in CATEGORY_TO_OWASP:
        return CATEGORY_TO_OWASP[category]
    return ("", "", "")


#: Classes de vulnerabilidade que cada adapter **exercita** (independente de
#: achar algo) — base da dimensão "testado" da matriz de cobertura. Fonte
#: única: as classes são resolvidas por ``resolve_owasp`` para derivar os
#: códigos OWASP cobertos, evitando duplicar o mapeamento.
ADAPTER_TESTED_CLASSES: dict[str, list[str]] = {
    "web-scan": [
        "injection.xss",
        "injection.sqli-error",
        "injection.sqli-boolean",
        "injection.path-traversal",
        "injection.open-redirect",
        "injection.ssti",
        "injection.command-injection",
        "injection.ssrf",
        "cors.misconfig",
        "exposure.git",
        "exposure.env",
        "exposure.actuator",
        "web-headers",
        "cookie",
        "http-method",
        "access-control.forced-browsing",
        "access-control.idor",
        "auth.user-enumeration",
        "auth.weak-session",
        "auth.no-rate-limit",
        "integrity.missing-sri",
        "integrity.vulnerable-js",
        "crypto.cleartext-credentials",
        "crypto.mixed-content",
        "misconfig.debug-mode",
        "misconfig.verbose-error",
    ],
    "tls": ["tls", "certificate"],
    "cve-lookup": ["software"],
    "default-creds": ["credential.default"],
    "zone-transfer": ["dns.zone-transfer"],
    "email-security": ["email-security"],
    "subdomain-enum": ["subdomain.takeover"],
    "dns": ["dns"],
}


def adapter_coverage(adapter_name: str) -> tuple[set[str], set[str]]:
    """Códigos OWASP (2021, 2025) que um adapter cobre — para a matriz.

    Deriva a cobertura resolvendo cada classe testada pelo adapter via
    ``resolve_owasp`` (não duplica o mapeamento). Retorna dois conjuntos de
    códigos (edição 2021, edição 2025).
    """
    codes_2021: set[str] = set()
    codes_2025: set[str] = set()
    for cls in ADAPTER_TESTED_CLASSES.get(adapter_name, []):
        if "." in cls:
            o21, o25, _ = resolve_owasp(playbook_key=cls)
        else:
            o21, o25, _ = resolve_owasp(category=cls)
        if o21:
            codes_2021.add(o21)
        if o25:
            codes_2025.add(o25)
    return codes_2021, codes_2025
