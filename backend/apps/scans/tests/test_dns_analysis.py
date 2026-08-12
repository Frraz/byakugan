"""Testes das regras de segurança de e-mail (SPF/DMARC/DKIM) — puro, sem rede/DB."""

from __future__ import annotations

from apps.scans.dns_analysis import analyze_email_security


def _titles(findings):
    return [f["title"] for f in findings]


# --- Cenário saudável --------------------------------------------------------


def test_healthy_records_produce_no_findings():
    findings = analyze_email_security(
        spf_records=["v=spf1 include:_spf.google.com -all"],
        dmarc_records=["v=DMARC1; p=reject; rua=mailto:dmarc@empresa.com"],
        dkim_selectors_found=["google"],
        domain="empresa.com",
    )
    assert findings == []


def test_softfail_all_is_considered_healthy():
    findings = analyze_email_security(
        spf_records=["v=spf1 include:_spf.google.com ~all"],
        dmarc_records=["v=DMARC1; p=quarantine;"],
        dkim_selectors_found=["default"],
        domain="empresa.com",
    )
    assert findings == []


# --- SPF ----------------------------------------------------------------


def test_spf_absent():
    findings = analyze_email_security(
        spf_records=[],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Registro SPF ausente" in _titles(findings)


def test_spf_bare_all_is_weak():
    findings = analyze_email_security(
        spf_records=["v=spf1 include:_spf.google.com all"],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Registro SPF com política permissiva" in _titles(findings)


def test_spf_plus_all_is_weak():
    findings = analyze_email_security(
        spf_records=["v=spf1 include:_spf.google.com +all"],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Registro SPF com política permissiva" in _titles(findings)


def test_spf_neutral_all_is_weak():
    findings = analyze_email_security(
        spf_records=["v=spf1 include:_spf.google.com ?all"],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Registro SPF com política permissiva" in _titles(findings)


def test_spf_hardfail_all_is_not_flagged():
    findings = analyze_email_security(
        spf_records=["v=spf1 include:_spf.google.com -all"],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Registro SPF com política permissiva" not in _titles(findings)


def test_spf_softfail_all_is_not_flagged():
    findings = analyze_email_security(
        spf_records=["v=spf1 include:_spf.google.com ~all"],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Registro SPF com política permissiva" not in _titles(findings)


def test_spf_does_not_false_positive_on_embedded_all_substring():
    """'mailall.example.com' não deve disparar o check de 'all' fraco."""
    findings = analyze_email_security(
        spf_records=["v=spf1 include:mailall.example.com ~all"],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Registro SPF com política permissiva" not in _titles(findings)


# --- DMARC ----------------------------------------------------------------


def test_dmarc_absent():
    findings = analyze_email_security(
        spf_records=["v=spf1 -all"], dmarc_records=[], dkim_selectors_found=["x"], domain="d"
    )
    assert "Registro DMARC ausente" in _titles(findings)


def test_dmarc_p_none_is_flagged():
    findings = analyze_email_security(
        spf_records=["v=spf1 -all"],
        dmarc_records=["v=DMARC1; p=none; rua=mailto:x@d.com"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Política DMARC permissiva (p=none)" in _titles(findings)


def test_dmarc_p_quarantine_not_flagged():
    findings = analyze_email_security(
        spf_records=["v=spf1 -all"],
        dmarc_records=["v=DMARC1; p=quarantine;"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Política DMARC permissiva (p=none)" not in _titles(findings)


def test_dmarc_p_reject_not_flagged():
    findings = analyze_email_security(
        spf_records=["v=spf1 -all"],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=["x"],
        domain="d",
    )
    assert "Política DMARC permissiva (p=none)" not in _titles(findings)


# --- DKIM ----------------------------------------------------------------


def test_dkim_no_common_selector_found():
    findings = analyze_email_security(
        spf_records=["v=spf1 -all"],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=[],
        domain="d",
    )
    assert "Nenhum seletor DKIM comum encontrado" in _titles(findings)


def test_dkim_selector_found_not_flagged():
    findings = analyze_email_security(
        spf_records=["v=spf1 -all"],
        dmarc_records=["v=DMARC1; p=reject;"],
        dkim_selectors_found=["default"],
        domain="d",
    )
    assert "Nenhum seletor DKIM comum encontrado" not in _titles(findings)


# --- Tudo ausente / RN008 -----------------------------------------------------


def test_everything_absent_produces_three_findings():
    findings = analyze_email_security(
        spf_records=[], dmarc_records=[], dkim_selectors_found=[], domain="d"
    )
    assert len(findings) == 3
    titles = _titles(findings)
    assert "Registro SPF ausente" in titles
    assert "Registro DMARC ausente" in titles
    assert "Nenhum seletor DKIM comum encontrado" in titles


def test_all_findings_are_rn008_complete_and_categorized():
    findings = analyze_email_security(
        spf_records=[], dmarc_records=[], dkim_selectors_found=[], domain="d"
    )
    for finding in findings:
        assert finding["description"].strip()
        assert finding["evidence"].strip()
        assert finding["recommendation"].strip()
        assert finding["category"] == "email-security"
        assert finding["severity"] in {"critical", "high", "medium", "low", "info"}
