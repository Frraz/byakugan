"""Testes das assinaturas de banner grabbing (puro, sem rede/DB)."""

from __future__ import annotations

from apps.scans.banners import parse_banner


def test_empty_banner_returns_nothing():
    assert parse_banner(22, b"") == []


def test_unrecognized_banner_returns_nothing():
    assert parse_banner(9999, b"nothing we know about\r\n") == []


def test_ssh_banner_extracts_product_and_version():
    raw = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    matches = parse_banner(22, raw)
    assert matches == [{"product": "OpenSSH", "version": "8.2p1", "service_name": "ssh"}]


def test_ftp_banner_vsftpd():
    raw = b"220 (vsFTPd 3.0.3)\r\n"
    matches = parse_banner(21, raw)
    assert len(matches) == 1
    assert matches[0]["service_name"] == "ftp"
    assert matches[0]["version"] == "3.0.3"


def test_ftp_banner_proftpd():
    raw = b"220 ProFTPD 1.3.5e Server ready.\r\n"
    matches = parse_banner(21, raw)
    assert matches[0]["product"] == "ProFTPD"
    assert matches[0]["version"] == "1.3.5"  # sufixo "e" não é [\d.] — versão numérica


def test_smtp_banner_postfix():
    raw = b"220 mail.example.com ESMTP Postfix\r\n"
    matches = parse_banner(25, raw)
    assert matches[0]["service_name"] == "smtp"
    assert matches[0]["version"] is None


def test_smtp_banner_sendmail_with_version():
    raw = b"220 example.com ESMTP Sendmail 8.15.2/8.15.2\r\n"
    matches = parse_banner(25, raw)
    assert matches[0]["version"] == "8.15.2"


def test_redis_pong_without_version():
    raw = b"+PONG\r\n"
    matches = parse_banner(6379, raw)
    assert matches == [{"product": "Redis", "version": None, "service_name": "redis"}]


def test_redis_info_with_version():
    raw = b"+PONG\r\nredis_version:7.2.4\r\n"
    matches = parse_banner(6379, raw)
    assert matches[0]["version"] == "7.2.4"


def test_redis_requires_pong_prefix():
    """Um banner que não começa com +PONG não deve ser confundido com Redis."""
    assert parse_banner(6379, b"some other data") == []


def test_mysql_handshake_v10():
    # cabeçalho de pacote (4 bytes, irrelevantes aqui) + protocolo v10 (0x0a)
    # + versão terminada em NUL + resto do handshake (ignorado).
    raw = b"\x00\x00\x00\x00" + b"\x0a" + b"8.0.34\x00" + b"restodohandshake"
    matches = parse_banner(3306, raw)
    assert matches == [{"product": "MySQL", "version": "8.0.34", "service_name": "mysql"}]


def test_mariadb_handshake_detected_by_version_string():
    raw = b"\x00\x00\x00\x00" + b"\x0a" + b"5.5.5-10.6.16-MariaDB\x00" + b"resto"
    matches = parse_banner(3306, raw)
    assert matches[0]["product"] == "MariaDB"
    assert matches[0]["version"] == "5.5.5-10.6.16-MariaDB"


def test_mysql_handshake_wrong_protocol_version_ignored():
    raw = b"\x00\x00\x00\x00" + b"\x09" + b"8.0.34\x00"  # protocolo != 0x0a
    assert parse_banner(3306, raw) == []


def test_mysql_handshake_too_short_ignored():
    assert parse_banner(3306, b"\x00\x00") == []


def test_telnet_iac_detected():
    raw = b"\xff\xfb\x01\xff\xfb\x03"
    matches = parse_banner(23, raw)
    assert matches == [{"product": "telnet", "version": None, "service_name": "telnet"}]


def test_pop3_dovecot():
    raw = b"+OK Dovecot ready.\r\n"
    matches = parse_banner(110, raw)
    assert matches[0]["service_name"] == "pop3"


def test_imap_dovecot():
    raw = b"* OK Dovecot ready.\r\n"
    matches = parse_banner(143, raw)
    assert matches[0]["service_name"] == "imap"


def test_matcher_priority_ssh_before_others():
    """Um banner SSH nunca deveria acidentalmente casar outra assinatura antes."""
    raw = b"SSH-2.0-OpenSSH_9.6\r\n"
    matches = parse_banner(22, raw)
    assert matches[0]["service_name"] == "ssh"
