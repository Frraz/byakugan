"""Regras de análise de segurança de e-mail via DNS (Fase 3 — DNS & Subdomínios).

Regras puras (sem I/O): interpretam registros TXT de SPF/DMARC já
consultados pelo adapter (``EmailSecurityAdapter``) e a lista de seletores
DKIM comuns que resolveram, produzindo findings sem CVE associado. Mesmo
padrão de ``cve.py``/``signatures.py``/``tls_analysis.py``.
"""

from __future__ import annotations

import re
from typing import Any

#: Prefixo que identifica um TXT record como SPF (RFC 7208).
SPF_PREFIX = "v=spf1"
#: Prefixo que identifica um TXT record como DMARC (RFC 7489), consultado em
#: ``_dmarc.<domínio>``.
DMARC_PREFIX = "v=dmarc1"

#: Qualificadores fracos do mecanismo "all" do SPF: "+all" permite qualquer
#: remetente (equivalente a não ter SPF); "?all" é neutro (não afirma nada).
_WEAK_ALL_RE = re.compile(r"(?<![\w~+?-])(?:\+|\?)?all\b", re.IGNORECASE)
_STRICT_ALL_RE = re.compile(r"[~-]all\b", re.IGNORECASE)


def _finding(
    *,
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: str,
    recommendation: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _check_spf(spf_records: list[str]) -> list[dict[str, Any]]:
    if not spf_records:
        return [
            _finding(
                title="Registro SPF ausente",
                severity="medium",
                category="email-security",
                description=(
                    "O domínio não publica um registro SPF (TXT `v=spf1`). Sem SPF, "
                    "servidores de e-mail não têm como validar se um remetente está "
                    "autorizado a enviar em nome do domínio — facilita spoofing/phishing."
                ),
                evidence="Nenhum TXT record iniciando com 'v=spf1' encontrado.",
                recommendation="Publicar um registro SPF listando os servidores de envio autorizados.",
            )
        ]

    findings = []
    for record in spf_records:
        if _STRICT_ALL_RE.search(record):
            continue  # -all ou ~all: mecanismo "all" configurado de forma restritiva
        weak_match = _WEAK_ALL_RE.search(record)
        if weak_match:
            qualifier = "+all" if not weak_match.group().startswith("?") else "?all"
            findings.append(
                _finding(
                    title="Registro SPF com política permissiva",
                    severity="medium",
                    category="email-security",
                    description=(
                        f"O SPF usa o qualificador '{qualifier}' no mecanismo 'all', que "
                        "permite (ou não rejeita) e-mails de qualquer servidor, "
                        "esvaziando o propósito do SPF."
                    ),
                    evidence=f"Registro SPF: {record}",
                    recommendation="Usar '-all' (hard fail) ou, no mínimo, '~all' (soft fail).",
                )
            )
    return findings


def _check_dmarc(dmarc_records: list[str]) -> list[dict[str, Any]]:
    if not dmarc_records:
        return [
            _finding(
                title="Registro DMARC ausente",
                severity="medium",
                category="email-security",
                description=(
                    "O domínio não publica um registro DMARC (TXT `v=DMARC1` em "
                    "`_dmarc.<domínio>`). Sem DMARC, não há política definida para "
                    "e-mails que falham SPF/DKIM, nem relatórios de abuso do domínio."
                ),
                evidence="Nenhum TXT record 'v=DMARC1' encontrado em _dmarc.<domínio>.",
                recommendation="Publicar um registro DMARC com política ao menos 'p=quarantine'.",
            )
        ]

    findings = []
    for record in dmarc_records:
        if re.search(r"p\s*=\s*none", record, re.IGNORECASE):
            findings.append(
                _finding(
                    title="Política DMARC permissiva (p=none)",
                    severity="low",
                    category="email-security",
                    description=(
                        "O DMARC está configurado com 'p=none' — apenas monitora, sem "
                        "rejeitar ou colocar em quarentena e-mails que falham "
                        "autenticação. Não protege efetivamente contra spoofing."
                    ),
                    evidence=f"Registro DMARC: {record}",
                    recommendation=(
                        "Evoluir a política para 'p=quarantine' e, quando confiante nos "
                        "relatórios, para 'p=reject'."
                    ),
                )
            )
    return findings


def _check_dkim(dkim_selectors_found: list[str]) -> list[dict[str, Any]]:
    if dkim_selectors_found:
        return []
    return [
        _finding(
            title="Nenhum seletor DKIM comum encontrado",
            severity="low",
            category="email-security",
            description=(
                "Nenhum dos seletores DKIM comumente usados resolveu um registro TXT "
                "em `<seletor>._domainkey.<domínio>`. Como o seletor é arbitrário, isso "
                "não confirma que DKIM está ausente — apenas que não foi possível "
                "confirmá-lo com os seletores testados."
            ),
            evidence="Nenhum TXT record encontrado para os seletores DKIM testados.",
            recommendation=(
                "Confirmar manualmente se DKIM está configurado (consultar o provedor "
                "de e-mail pelo seletor real); se ausente, habilitar assinatura DKIM."
            ),
        )
    ]


def analyze_email_security(
    *,
    spf_records: list[str],
    dmarc_records: list[str],
    dkim_selectors_found: list[str],
    domain: str,
) -> list[dict[str, Any]]:
    """Avalia a postura de segurança de e-mail (SPF/DMARC/DKIM) do domínio.

    Args:
        spf_records: TXT records do domínio que começam com ``v=spf1``.
        dmarc_records: TXT records de ``_dmarc.<domain>`` que começam com
            ``v=DMARC1``.
        dkim_selectors_found: Seletores (de uma lista curada testada pelo
            adapter) que resolveram um TXT record em ``<seletor>._domainkey``.
        domain: Domínio avaliado (não usado no julgamento, mantido no
            contrato para findings futuras que precisem referenciá-lo).

    Returns:
        Lista de dicts de finding (``title``/``severity``/``category``/
        ``description``/``evidence``/``recommendation``) — sem CVE associado.
    """
    return [
        *_check_spf(spf_records),
        *_check_dmarc(dmarc_records),
        *_check_dkim(dkim_selectors_found),
    ]
