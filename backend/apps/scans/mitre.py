"""Mapeamento MITRE ATT&CK (Enterprise) por classe de vulnerabilidade.

Terceira dimensão de classificação de um ``Finding``, junto de OWASP
2021/2025 + CWE (``owasp.py``) — o padrão de relatório que um red/purple
team sênior usa de fato: não só "que tipo de bug é" (CWE) e "em que
categoria do Top 10 cai" (OWASP), mas **que técnica de ataque do mundo real
isso corresponde** (ATT&CK), a linguagem comum entre red team, blue team e
ferramentas de SIEM/SOAR (ATT&CK Navigator).

**Honestidade por design, igual a ``owasp.LIMITED_COVERAGE``**: só ~27 das
42 classes têm uma técnica mapeada aqui — exatamente as que correspondem a
uma técnica ATT&CK real e inequívoca. Classes sem mapeamento (ex.:
``misconfig.weak-csp`` — fraqueza de controle, não uma técnica de ataque em
si; ``exposure.cloud-storage-reference`` — nunca executado, então não há
técnica *comprovada*) ficam deliberadamente vazias em vez de forçar uma
correspondência especulativa. **Revisão humana recomendada** antes de usar
este mapeamento num relatório de engajamento real — é um ponto de partida
correto, não uma autoridade substituta do analista.

Fonte: MITRE ATT&CK Enterprise (https://attack.mitre.org/).
"""

from __future__ import annotations

#: Técnica ATT&CK → nome oficial (inglês, como o MITRE publica).
MITRE_TECHNIQUES: dict[str, str] = {
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1606": "Forge Web Credentials",
    "T1078": "Valid Accounts",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1110": "Brute Force",
    "T1589": "Gather Victim Identity Information",
    "T1557": "Adversary-in-the-Middle",
    "T1590.002": "Gather Victim Network Information: DNS",
    "T1584.001": "Compromise Infrastructure: Domains",
}

#: ``Finding.playbook_key`` → técnica ATT&CK primária.
CLASS_TO_MITRE: dict[str, str] = {
    # --- T1190: exploração direta de uma falha na aplicação pública ---
    "injection.sqli-error": "T1190",
    "injection.sqli-boolean": "T1190",
    "injection.path-traversal": "T1190",
    "injection.xss": "T1190",
    "injection.ssti": "T1190",
    "injection.ssrf": "T1190",
    "injection.open-redirect": "T1190",
    "injection.host-header": "T1190",
    "injection.nosqli": "T1190",
    "injection.ldap": "T1190",
    "injection.crlf": "T1190",
    "access-control.forced-browsing": "T1190",
    "access-control.idor": "T1190",
    "access-control.csrf": "T1190",
    "integrity.java-deserialization": "T1190",
    "integrity.php-object-injection": "T1190",
    "integrity.viewstate-exposed": "T1190",
    # --- Técnicas mais específicas que a exploração genérica ---
    "injection.command-injection": "T1059",
    "auth.jwt-weak": "T1606",
    "credential.default": "T1078",
    "exposure.git": "T1552.001",
    "exposure.env": "T1552.001",
    "auth.no-rate-limit": "T1110",
    "auth.user-enumeration": "T1589",
    "crypto.cleartext-credentials": "T1557",
    "dns.zone-transfer": "T1590.002",
    "subdomain.takeover": "T1584.001",
}


def resolve_mitre(playbook_key: str) -> tuple[str, str]:
    """Resolve ``(técnica, nome)`` de um ``playbook_key`` — ``("", "")`` se não mapeado.

    Função pura, mesmo padrão de ``owasp.resolve_owasp``: nunca levanta
    erro, nunca inventa uma técnica para uma classe sem correspondência
    confiável.
    """
    technique = CLASS_TO_MITRE.get(playbook_key, "")
    if not technique:
        return "", ""
    return technique, MITRE_TECHNIQUES.get(technique, "")
