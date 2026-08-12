"""Assinaturas de banner grabbing TCP (Fase 1 — Network & Services).

Regras puras (sem I/O) que interpretam o banner bruto lido logo após a
conexão TCP (ou após um "nudge" mínimo para protocolos que não bannerizam
sozinhos — ver ``_BANNER_NUDGES`` em ``adapters.py``) e derivam produto/
versão do serviço. Mesmo padrão de ``signatures.py`` (fingerprint HTTP):
mantém o reconhecimento fora do adapter de rede, testável sem socket real.

Cada assinatura devolve ``{"product", "version", "service_name"}`` — o
mesmo shape que ``adapters.PortDiscoveryAdapter`` mescla no ``RawResult``
de ``kind="service"``, alimentando o *technology profile* que o
``CveLookupAdapter`` correlaciona com CVEs na fase seguinte.
"""

from __future__ import annotations

import re
from typing import Any

#: Prefixo "SSH-<protover>-" seguido do token de software (sem espaço).
_SSH_PREFIX_RE = re.compile(rb"^SSH-\d\.\d-(\S+)", re.IGNORECASE)
#: Separador [_-] imediatamente antes de uma versão (começa em dígito), no
#: FINAL do token — ex.: "OpenSSH_8.2p1" → produto "OpenSSH", versão "8.2p1".
#: Duas etapas (prefixo + split) em vez de um regex único: ``\w`` inclui
#: dígito/underscore, então um único padrão guloso confunde produto e versão
#: (ex.: capturaria "OpenSSH_8.2p1" inteiro como "produto").
_SSH_VERSION_SPLIT_RE = re.compile(rb"[_-](\d[\w.]*)$")
_FTP_RE = re.compile(
    rb"220[- ].*?\b(vsftpd|proftpd|pure-ftpd|filezilla)\b[\s(]*v?([\d][\d.]*)?",
    re.IGNORECASE,
)
_SMTP_RE = re.compile(
    rb"220[- ].*?\b(postfix|exim|sendmail|microsoft esmtp)\b[\s/]*v?([\d][\d.]*)?",
    re.IGNORECASE,
)
_POP3_RE = re.compile(rb"\+OK.*?\b(dovecot|cyrus)\b[\s/]*v?([\d][\d.]*)?", re.IGNORECASE)
_IMAP_RE = re.compile(rb"\*\s+OK.*?\b(dovecot|cyrus)\b[\s/]*v?([\d][\d.]*)?", re.IGNORECASE)
_REDIS_PONG_RE = re.compile(rb"^\+PONG", re.IGNORECASE)
_REDIS_VERSION_RE = re.compile(rb"redis_version:([\d.]+)", re.IGNORECASE)
#: Início de negociação Telnet (IAC — Interpret As Command).
_TELNET_IAC = b"\xff"


def _text(raw: bytes | None) -> str | None:
    if not raw:
        return None
    return raw.decode("ascii", errors="ignore")


def _match_ssh(raw: bytes) -> dict[str, Any] | None:
    prefix_match = _SSH_PREFIX_RE.match(raw)
    if not prefix_match:
        return None
    token = prefix_match.group(1)  # ex.: b"OpenSSH_8.2p1"
    version_match = _SSH_VERSION_SPLIT_RE.search(token)
    if version_match:
        product, version = token[: version_match.start()], version_match.group(1)
    else:
        product, version = token, None
    return {"product": _text(product), "version": _text(version), "service_name": "ssh"}


def _match_ftp(raw: bytes) -> dict[str, Any] | None:
    match = _FTP_RE.search(raw)
    if not match:
        return None
    return {
        "product": _text(match.group(1)),
        "version": _text(match.group(2)),
        "service_name": "ftp",
    }


def _match_smtp(raw: bytes) -> dict[str, Any] | None:
    match = _SMTP_RE.search(raw)
    if not match:
        return None
    return {
        "product": _text(match.group(1)),
        "version": _text(match.group(2)),
        "service_name": "smtp",
    }


def _match_pop3(raw: bytes) -> dict[str, Any] | None:
    match = _POP3_RE.search(raw)
    if not match:
        return None
    return {
        "product": _text(match.group(1)),
        "version": _text(match.group(2)),
        "service_name": "pop3",
    }


def _match_imap(raw: bytes) -> dict[str, Any] | None:
    match = _IMAP_RE.search(raw)
    if not match:
        return None
    return {
        "product": _text(match.group(1)),
        "version": _text(match.group(2)),
        "service_name": "imap",
    }


def _match_redis(raw: bytes) -> dict[str, Any] | None:
    if not _REDIS_PONG_RE.match(raw):
        return None
    version_match = _REDIS_VERSION_RE.search(raw)
    version = _text(version_match.group(1)) if version_match else None
    return {"product": "Redis", "version": version, "service_name": "redis"}


def _match_mysql(raw: bytes) -> dict[str, Any] | None:
    """Extrai a versão do handshake binário inicial do MySQL/MariaDB.

    Formato (protocolo v10): 4 bytes de cabeçalho do pacote (tamanho +
    sequência) seguidos do byte de versão do protocolo e da string de
    versão terminada em NUL.
    """
    if len(raw) < 6 or raw[4] != 0x0A:
        return None
    terminator = raw.find(b"\x00", 5)
    if terminator == -1:
        return None
    version_bytes = raw[5:terminator]
    if not version_bytes or not re.match(rb"^\d[\w.\-]*$", version_bytes):
        return None
    version_str = version_bytes.decode("ascii", errors="ignore")
    product = "MariaDB" if "mariadb" in version_str.lower() else "MySQL"
    return {"product": product, "version": version_str, "service_name": "mysql"}


def _match_telnet(raw: bytes) -> dict[str, Any] | None:
    if not raw.startswith(_TELNET_IAC):
        return None
    return {"product": "telnet", "version": None, "service_name": "telnet"}


_MATCHERS = (
    _match_ssh,
    _match_ftp,
    _match_smtp,
    _match_pop3,
    _match_imap,
    _match_redis,
    _match_mysql,
    _match_telnet,
)


def parse_banner(port: int, raw: bytes) -> list[dict[str, Any]]:
    """Interpreta o banner bruto de uma porta TCP e deriva produto/versão.

    Args:
        port: Porta de origem (não decide a assinatura — a detecção é pelo
            conteúdo, já que serviços comumente rodam fora da porta padrão;
            mantido no contrato para futuras assinaturas dependentes de porta).
        raw: Bytes lidos da conexão (pode ser vazio).

    Returns:
        Lista com o dict da primeira assinatura que casar (``[]`` se
        nenhuma reconhecer o banner) — shape de lista por consistência com
        ``signatures.fingerprint_http``, ainda que hoje só um produto por
        porta seja identificado.
    """
    if not raw:
        return []
    for matcher in _MATCHERS:
        result = matcher(raw)
        if result:
            return [result]
    return []
