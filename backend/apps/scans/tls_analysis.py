"""Regras de análise de TLS e certificado (Fase 2 — TLS & Certificados).

Regras puras (sem I/O): traduzem o que ``adapters.TlsAdapter`` coleta da rede
(versões de protocolo suportadas, cipher negociado, campos do certificado)
em findings prontos para persistência. Mesmo padrão de ``cve.py``/
``signatures.py`` — isola o julgamento de risco da coleta de rede, testável
sem handshake TLS real ou dependência de ``cryptography`` nos testes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

#: Protocolos TLS/SSL obsoletos (RFC 8996 depreca TLS 1.0/1.1; SSLv2/v3 têm
#: vulnerabilidades conhecidas há muito mais tempo). Mesmo conjunto usado em
#: ``adapters.DEPRECATED_TLS`` para a evidência da tecnologia.
DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}

#: Substrings do nome do cipher que indicam algoritmo/modo fraco ou obsoleto.
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "EXPORT", "NULL", "MD5")
WEAK_CIPHER_MIN_BITS = 128

#: Tamanho mínimo de chave (bits) considerado seguro por tipo de algoritmo —
#: chaves EC não entram aqui (a equivalência de força usa curva, não bits).
MIN_KEY_BITS = {"RSA": 2048, "DSA": 2048}

WEAK_SIGNATURE_HASHES = ("md5", "sha1")
CERT_EXPIRING_SOON_DAYS = 30


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


def _check_deprecated_protocol(supported_versions: list[str]) -> dict[str, Any] | None:
    found = sorted(v for v in supported_versions if v in DEPRECATED_PROTOCOLS)
    if not found:
        return None
    versions = ", ".join(found)
    return _finding(
        title="Protocolo TLS obsoleto habilitado",
        severity="medium",
        category="tls",
        description=(
            f"O serviço aceita conexões usando protocolo(s) obsoleto(s): {versions}. "
            "Versões antigas de TLS/SSL têm vulnerabilidades criptográficas conhecidas "
            "(ex.: POODLE, BEAST) e são desaconselhadas pela RFC 8996."
        ),
        evidence=f"Handshake bem-sucedido usando: {versions}.",
        recommendation=(
            "Desabilitar SSLv2/SSLv3/TLSv1.0/TLSv1.1 no servidor, mantendo apenas TLSv1.2+."
        ),
    )


def _check_weak_cipher(cipher: tuple[str, int] | None) -> dict[str, Any] | None:
    if cipher is None:
        return None
    name, bits = cipher
    is_weak_name = any(marker in name.upper() for marker in WEAK_CIPHER_MARKERS)
    is_weak_bits = bits < WEAK_CIPHER_MIN_BITS
    if not (is_weak_name or is_weak_bits):
        return None
    return _finding(
        title="Cipher TLS fraco negociado",
        severity="high",
        category="tls",
        description=(
            f"O serviço negociou o cipher '{name}' ({bits} bits), considerado fraco ou "
            "obsoleto (algoritmo/modo vulnerável ou força criptográfica insuficiente)."
        ),
        evidence=f"Cipher negociado: {name}, {bits} bits.",
        recommendation=(
            "Restringir a configuração TLS do servidor a ciphers modernos (AEAD — "
            "AES-GCM/ChaCha20-Poly1305), removendo suítes RC4/3DES/EXPORT/NULL e "
            "exigindo no mínimo 128 bits efetivos."
        ),
    )


def _looks_like_ip_or_cidr(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _hostname_matches(hostname: str, pattern: str) -> bool:
    """Compara ``hostname`` contra uma entrada de SAN/CN (com suporte a `*.`)."""
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if hostname == pattern:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        if not hostname.endswith(suffix):
            return False
        prefix = hostname[: -len(suffix)]
        # Wildcard cobre só um label (ex.: "*.example.com" não casa "a.b.example.com").
        return bool(prefix) and "." not in prefix
    return False


def _extract_dn_field(dn: str, key: str) -> str | None:
    """Extrai um campo (ex.: ``CN``) de um Distinguished Name ``"CN=x,O=y"``."""
    for part in (dn or "").split(","):
        part = part.strip()
        if part.upper().startswith(f"{key.upper()}="):
            return part.split("=", 1)[1].strip()
    return None


def _check_expiry(cert_fields: dict[str, Any], now: datetime) -> dict[str, Any] | None:
    not_after: datetime = cert_fields["not_valid_after"]
    not_before: datetime = cert_fields["not_valid_before"]

    if not_after < now:
        return _finding(
            title="Certificado TLS expirado",
            severity="high",
            category="certificate",
            description=(
                f"O certificado apresentado expirou em {not_after:%Y-%m-%d}. Clientes "
                "modernos rejeitam ou alertam fortemente sobre certificados expirados."
            ),
            evidence=f"notAfter={not_after.isoformat()} (avaliado em {now.isoformat()}).",
            recommendation="Renovar o certificado imediatamente.",
        )

    if not_before > now:
        return _finding(
            title="Certificado TLS ainda não é válido",
            severity="medium",
            category="certificate",
            description=(
                f"O certificado só se torna válido em {not_before:%Y-%m-%d} — pode "
                "indicar emissão futura incorreta ou relógio do servidor dessincronizado."
            ),
            evidence=f"notBefore={not_before.isoformat()} (avaliado em {now.isoformat()}).",
            recommendation="Verificar a data de emissão do certificado e o relógio do servidor.",
        )

    days_left = (not_after - now).days
    if days_left < CERT_EXPIRING_SOON_DAYS:
        return _finding(
            title="Certificado TLS expirando em breve",
            severity="low",
            category="certificate",
            description=f"O certificado expira em {days_left} dia(s) ({not_after:%Y-%m-%d}).",
            evidence=f"notAfter={not_after.isoformat()}, {days_left} dia(s) restantes.",
            recommendation="Renovar o certificado antes do vencimento para evitar interrupção.",
        )

    return None


def _check_self_signed(cert_fields: dict[str, Any]) -> dict[str, Any] | None:
    issuer, subject = cert_fields.get("issuer"), cert_fields.get("subject")
    if not issuer or not subject or issuer != subject:
        return None
    return _finding(
        title="Certificado TLS autoassinado",
        severity="medium",
        category="certificate",
        description=(
            "O certificado é autoassinado (emissor e titular são a mesma entidade) — "
            "não é validado por uma Autoridade Certificadora confiável."
        ),
        evidence=f"issuer == subject == '{subject}'.",
        recommendation=(
            "Substituir por um certificado emitido por uma CA confiável (ex.: Let's "
            "Encrypt para uso público) fora de ambientes de laboratório."
        ),
    )


def _check_missing_san(cert_fields: dict[str, Any]) -> dict[str, Any] | None:
    if cert_fields.get("san"):
        return None
    return _finding(
        title="Certificado TLS sem Subject Alternative Name (SAN)",
        severity="medium",
        category="certificate",
        description=(
            "O certificado não possui extensão SAN. Navegadores modernos ignoram o "
            "campo CN e exigem SAN — a ausência causa erro de validação no cliente."
        ),
        evidence="Extensão subjectAltName ausente ou vazia.",
        recommendation="Reemitir o certificado incluindo os hostnames relevantes em SAN.",
    )


def _check_hostname_mismatch(cert_fields: dict[str, Any], hostname: str) -> dict[str, Any] | None:
    if _looks_like_ip_or_cidr(hostname):
        return None  # certificado por hostname não se aplica a alvo por IP puro

    san: list[str] = cert_fields.get("san") or []
    candidates = list(san)
    if not candidates:
        cn = _extract_dn_field(cert_fields.get("subject") or "", "CN")
        if cn:
            candidates = [cn]

    if not candidates:
        return None  # já coberto por "SAN ausente"; sem CN também, nada a comparar

    if any(_hostname_matches(hostname, candidate) for candidate in candidates):
        return None

    return _finding(
        title="Certificado TLS não corresponde ao hostname do alvo",
        severity="high",
        category="certificate",
        description=(
            f"O certificado apresentado não cobre '{hostname}' — nem em SAN nem no CN. "
            "Isso quebra a validação de identidade TLS e pode indicar configuração "
            "incorreta ou um serviço interceptando/adulterando a conexão."
        ),
        evidence=f"Alvo='{hostname}'; nomes no certificado={candidates}.",
        recommendation="Emitir/associar um certificado que cubra o hostname correto do serviço.",
    )


def _check_weak_key(cert_fields: dict[str, Any]) -> dict[str, Any] | None:
    key_type = cert_fields.get("key_type")
    key_size = cert_fields.get("key_size")
    minimum = MIN_KEY_BITS.get(key_type or "")
    if minimum is None or key_size is None or key_size >= minimum:
        return None
    return _finding(
        title=f"Chave {key_type} fraca no certificado TLS",
        severity="high",
        category="certificate",
        description=(
            f"A chave pública do certificado usa {key_type} de {key_size} bits, abaixo "
            f"do mínimo recomendado ({minimum} bits) — vulnerável a fatoração com "
            "recursos computacionais modernos."
        ),
        evidence=f"key_type={key_type}, key_size={key_size} bits.",
        recommendation=f"Reemitir o certificado com uma chave {key_type} de ao menos {minimum} bits.",
    )


def _check_weak_signature(cert_fields: dict[str, Any]) -> dict[str, Any] | None:
    algorithm = (cert_fields.get("signature_algorithm") or "").lower()
    weak = next((h for h in WEAK_SIGNATURE_HASHES if h in algorithm), None)
    if not weak:
        return None
    return _finding(
        title="Certificado TLS assinado com algoritmo de hash fraco",
        severity="high",
        category="certificate",
        description=(
            f"A assinatura do certificado usa {weak.upper()}, hash criptograficamente "
            "quebrado (ataques de colisão práticos) e rejeitado pelos navegadores "
            "modernos para certificados públicos."
        ),
        evidence=f"signature_algorithm={cert_fields.get('signature_algorithm')}.",
        recommendation="Reemitir o certificado com assinatura SHA-256 ou superior.",
    )


def analyze_tls(
    *,
    supported_versions: list[str],
    cipher: tuple[str, int] | None,
    cert_fields: dict[str, Any] | None,
    hostname: str,
    now: datetime,
) -> list[dict[str, Any]]:
    """Avalia a exposição TLS/certificado do alvo e retorna findings (sem CVE).

    Args:
        supported_versions: Protocolos que o servidor aceitou em um handshake
            (ex.: ``["TLSv1", "TLSv1.2", "TLSv1.3"]``) — ver ``TlsAdapter._probe_versions``.
        cipher: ``(nome, bits)`` do cipher negociado no handshake padrão, ou
            ``None`` se indisponível.
        cert_fields: Campos extraídos do certificado (``not_valid_before``,
            ``not_valid_after``, ``issuer``, ``subject``, ``san``, ``key_type``,
            ``key_size``, ``signature_algorithm``), ou ``None`` se o
            certificado não pôde ser obtido — nesse caso só as checagens de
            protocolo/cipher rodam.
        hostname: Alvo do scan, usado na checagem de hostname×certificado.
        now: Instante de referência (injetável para testes determinísticos).

    Returns:
        Lista de dicts de finding (``title``/``severity``/``category``/
        ``description``/``evidence``/``recommendation``) — sem CVE associado.
    """
    checks = [
        _check_deprecated_protocol(supported_versions),
        _check_weak_cipher(cipher),
    ]
    if cert_fields is not None:
        checks.extend(
            [
                _check_expiry(cert_fields, now),
                _check_self_signed(cert_fields),
                _check_missing_san(cert_fields),
                _check_hostname_mismatch(cert_fields, hostname),
                _check_weak_key(cert_fields),
                _check_weak_signature(cert_fields),
            ]
        )
    return [finding for finding in checks if finding is not None]
