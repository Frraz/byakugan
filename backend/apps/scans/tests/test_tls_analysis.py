"""Testes das regras de análise de TLS/certificado (puro, sem rede/DB)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from apps.scans.tls_analysis import analyze_tls

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _healthy_cert(**overrides) -> dict:
    cert = {
        "not_valid_before": NOW - timedelta(days=10),
        "not_valid_after": NOW + timedelta(days=300),
        "issuer": "CN=Trusted CA",
        "subject": "CN=example.com",
        "san": ["example.com", "www.example.com"],
        "key_type": "RSA",
        "key_size": 2048,
        "signature_algorithm": "sha256",
    }
    cert.update(overrides)
    return cert


def test_healthy_cert_and_modern_tls_produce_no_findings():
    findings = analyze_tls(
        supported_versions=["TLSv1.2", "TLSv1.3"],
        cipher=("TLS_AES_256_GCM_SHA384", 256),
        cert_fields=_healthy_cert(),
        hostname="example.com",
        now=NOW,
    )
    assert findings == []


def test_no_cert_still_runs_protocol_and_cipher_checks():
    findings = analyze_tls(
        supported_versions=["TLSv1"],
        cipher=("RC4-SHA", 128),
        cert_fields=None,
        hostname="example.com",
        now=NOW,
    )
    titles = {f["title"] for f in findings}
    assert "Protocolo TLS obsoleto habilitado" in titles
    assert "Cipher TLS fraco negociado" in titles
    assert len(findings) == 2  # nenhuma checagem de certificado sem cert_fields


def test_no_cert_and_modern_protocol_produces_nothing():
    assert (
        analyze_tls(
            supported_versions=["TLSv1.3"],
            cipher=("TLS_AES_256_GCM_SHA384", 256),
            cert_fields=None,
            hostname="example.com",
            now=NOW,
        )
        == []
    )


# --- Protocolo/cipher --------------------------------------------------------


def test_deprecated_protocol_flags_each_found_version():
    findings = analyze_tls(
        supported_versions=["TLSv1", "TLSv1.1", "TLSv1.2"],
        cipher=None,
        cert_fields=None,
        hostname="example.com",
        now=NOW,
    )
    assert len(findings) == 1
    assert "TLSv1" in findings[0]["evidence"]
    assert "TLSv1.1" in findings[0]["evidence"]
    assert "TLSv1.2" not in findings[0]["evidence"]
    assert findings[0]["category"] == "tls"


def test_modern_only_protocols_do_not_flag():
    assert (
        analyze_tls(
            supported_versions=["TLSv1.2", "TLSv1.3"],
            cipher=None,
            cert_fields=None,
            hostname="example.com",
            now=NOW,
        )
        == []
    )


def test_weak_cipher_by_name():
    findings = analyze_tls(
        supported_versions=[],
        cipher=("ECDHE-RSA-RC4-SHA", 128),
        cert_fields=None,
        hostname="example.com",
        now=NOW,
    )
    assert len(findings) == 1
    assert findings[0]["category"] == "tls"
    assert findings[0]["severity"] == "high"


def test_weak_cipher_by_low_bits():
    findings = analyze_tls(
        supported_versions=[],
        cipher=("SOME-STRONG-SOUNDING-NAME", 64),
        cert_fields=None,
        hostname="example.com",
        now=NOW,
    )
    assert len(findings) == 1


def test_strong_cipher_does_not_flag():
    assert (
        analyze_tls(
            supported_versions=[],
            cipher=("TLS_AES_256_GCM_SHA384", 256),
            cert_fields=None,
            hostname="example.com",
            now=NOW,
        )
        == []
    )


def test_no_cipher_negotiated_skips_check():
    assert (
        analyze_tls(supported_versions=[], cipher=None, cert_fields=None, hostname="x", now=NOW)
        == []
    )


# --- Certificado: validade ---------------------------------------------------


def test_expired_certificate():
    cert = _healthy_cert(not_valid_after=NOW - timedelta(days=5))
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    titles = [f["title"] for f in findings]
    assert "Certificado TLS expirado" in titles
    # Expirado não deve TAMBÉM disparar "expirando em breve".
    assert "Certificado TLS expirando em breve" not in titles


def test_not_yet_valid_certificate():
    cert = _healthy_cert(
        not_valid_before=NOW + timedelta(days=5), not_valid_after=NOW + timedelta(days=400)
    )
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert any(f["title"] == "Certificado TLS ainda não é válido" for f in findings)


def test_certificate_expiring_soon():
    cert = _healthy_cert(not_valid_after=NOW + timedelta(days=10))
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    match = [f for f in findings if f["title"] == "Certificado TLS expirando em breve"]
    assert len(match) == 1
    assert match[0]["severity"] == "low"


def test_certificate_valid_for_a_year_does_not_flag_expiry():
    cert = _healthy_cert()
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert not any("expir" in f["title"].lower() for f in findings)


# --- Certificado: self-signed / SAN / hostname -------------------------------


def test_self_signed_certificate():
    cert = _healthy_cert(issuer="CN=example.com", subject="CN=example.com")
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert any(f["title"] == "Certificado TLS autoassinado" for f in findings)


def test_ca_signed_certificate_not_flagged_as_self_signed():
    cert = _healthy_cert(issuer="CN=Trusted CA", subject="CN=example.com")
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert not any(f["title"] == "Certificado TLS autoassinado" for f in findings)


def test_missing_san():
    cert = _healthy_cert(san=[])
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert any(f["title"] == "Certificado TLS sem Subject Alternative Name (SAN)" for f in findings)


def test_hostname_matches_exact_san_entry():
    cert = _healthy_cert(san=["example.com"])
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert not any(
        "hostname" in f["title"].lower() or "corresponde" in f["title"] for f in findings
    )


def test_hostname_matches_wildcard_san_entry():
    cert = _healthy_cert(san=["*.example.com"])
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="app.example.com", now=NOW
    )
    assert not any("corresponde" in f["title"] for f in findings)


def test_wildcard_does_not_match_multi_label_subdomain():
    cert = _healthy_cert(san=["*.example.com"])
    findings = analyze_tls(
        supported_versions=[],
        cipher=None,
        cert_fields=cert,
        hostname="a.b.example.com",
        now=NOW,
    )
    assert any("corresponde" in f["title"] for f in findings)


def test_hostname_mismatch_when_san_present_but_wrong():
    cert = _healthy_cert(san=["other.example.com"])
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    match = [f for f in findings if "corresponde" in f["title"]]
    assert len(match) == 1
    assert match[0]["severity"] == "high"


def test_hostname_mismatch_falls_back_to_cn_when_san_empty():
    cert = _healthy_cert(san=[], subject="CN=other.example.com")
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert any("corresponde" in f["title"] for f in findings)


def test_hostname_matches_cn_when_san_empty():
    cert = _healthy_cert(san=[], subject="CN=example.com")
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert not any("corresponde" in f["title"] for f in findings)


def test_hostname_check_skipped_for_ip_targets():
    cert = _healthy_cert(san=["example.com"])
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="192.168.0.10", now=NOW
    )
    assert not any("corresponde" in f["title"] for f in findings)


# --- Certificado: chave/assinatura fracas ------------------------------------


def test_weak_rsa_key():
    cert = _healthy_cert(key_type="RSA", key_size=1024)
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    match = [f for f in findings if "Chave" in f["title"]]
    assert len(match) == 1
    assert match[0]["severity"] == "high"


def test_strong_rsa_key_not_flagged():
    cert = _healthy_cert(key_type="RSA", key_size=4096)
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert not any("Chave" in f["title"] for f in findings)


def test_ec_key_never_flagged_as_weak():
    """Chaves EC não têm limiar em MIN_KEY_BITS — nunca disparam essa checagem."""
    cert = _healthy_cert(key_type="EC", key_size=256)
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert not any("Chave" in f["title"] for f in findings)


def test_weak_signature_sha1():
    cert = _healthy_cert(signature_algorithm="sha1")
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert any(
        f["title"] == "Certificado TLS assinado com algoritmo de hash fraco" for f in findings
    )


def test_weak_signature_md5():
    cert = _healthy_cert(signature_algorithm="md5")
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert any(
        f["title"] == "Certificado TLS assinado com algoritmo de hash fraco" for f in findings
    )


def test_strong_signature_not_flagged():
    cert = _healthy_cert(signature_algorithm="sha256")
    findings = analyze_tls(
        supported_versions=[], cipher=None, cert_fields=cert, hostname="example.com", now=NOW
    )
    assert not any("assinado" in f["title"] for f in findings)


# --- RN008: toda finding tem os 3 campos obrigatórios ------------------------


def test_all_findings_are_rn008_complete():
    cert = _healthy_cert(
        not_valid_after=NOW - timedelta(days=1),
        issuer="CN=x",
        subject="CN=x",
        san=[],
        key_size=512,
        signature_algorithm="md5",
    )
    findings = analyze_tls(
        supported_versions=["TLSv1"],
        cipher=("RC4-MD5", 40),
        cert_fields=cert,
        hostname="mismatch.example.com",
        now=NOW,
    )
    assert len(findings) >= 6
    for finding in findings:
        assert finding["description"].strip()
        assert finding["evidence"].strip()
        assert finding["recommendation"].strip()
        assert finding["severity"] in {"critical", "high", "medium", "low", "info"}
