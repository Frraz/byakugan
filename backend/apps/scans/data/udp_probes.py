"""Probes UDP leves para serviços comuns (Fase 1 — Network & Services).

UDP não tem handshake: para saber se algo está escutando, é preciso enviar
um payload que o protocolo realmente reconheça e aguardar qualquer resposta
— um datagrama genérico normalmente é descartado em silêncio. Cada probe
aqui é o **cabeçalho mínimo válido** do protocolo (não uma implementação
completa) — o objetivo é confirmar exposição, não interagir a fundo com o
serviço. Nenhum probe grava, altera ou autentica nada no alvo.
"""

from __future__ import annotations

# --- DNS (53): consulta CHAOS TXT "version.bind" — técnica padrão e
# inofensiva para identificar servidores DNS (muitos respondem a isso mesmo
# quando não respondem consultas normais de fora da rede autorizada). ---
_DNS_VERSION_BIND = (
    b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # header: id, flags, QDCOUNT=1
    b"\x07version\x04bind\x00"  # QNAME: version.bind
    b"\x00\x10\x00\x03"  # QTYPE=TXT(16), QCLASS=CHAOS(3)
)

# --- NTP (123): pacote de requisição de cliente NTPv3 (RFC 1305) — o
# primeiro byte codifica LI=0/VN=3/Mode=3 (client), restante zerado. ---
_NTP_CLIENT_REQUEST = b"\x1b" + b"\x00" * 47

# --- SNMP (161): GetRequest SNMPv1 (BER/ASN.1) para o OID sysDescr.0
# (1.3.6.1.2.1.1.1.0), community "public" — leitura pública padrão, somente
# consulta (GET), nunca SET. ---
_SNMP_GET_SYSDESCR = (
    b"\x30\x26"  # SEQUENCE, len=38 (mensagem SNMP)
    b"\x02\x01\x00"  # INTEGER version=0 (v1)
    b"\x04\x06public"  # OCTET STRING community="public"
    b"\xa0\x19"  # [0] GetRequest-PDU, len=25
    b"\x02\x01\x00"  # request-id=0
    b"\x02\x01\x00"  # error-status=0
    b"\x02\x01\x00"  # error-index=0
    b"\x30\x0e"  # SEQUENCE variable-bindings, len=14
    b"\x30\x0c"  # SEQUENCE varbind, len=12
    b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"  # OID 1.3.6.1.2.1.1.1.0
    b"\x05\x00"  # NULL (value)
)

# --- NetBIOS Name Service (137): NBSTAT query para o nome coringa "*"
# (codificação half-ASCII padrão RFC 1002) — enumera nomes NetBIOS do host,
# técnica clássica de nbtscan/nmap. ---
_NBNS_WILDCARD_NBSTAT = (
    b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # header: id, flags, QDCOUNT=1
    b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"  # NBNAME codificado (nome coringa "*")
    b"\x00\x21\x00\x01"  # QTYPE=NBSTAT(0x21), QCLASS=IN(1)
)

# --- mDNS (5353): consulta meta de descoberta de serviços
# (_services._dns-sd._udp.local PTR) — padrão para "quais serviços mDNS
# existem aqui", não mira um serviço específico. ---
_MDNS_SERVICES_QUERY = (
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # header: id=0, QDCOUNT=1
    b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"  # QNAME
    b"\x00\x0c\x00\x01"  # QTYPE=PTR(12), QCLASS=IN(1)
)

# --- IKE/ISAKMP (500): cabeçalho ISAKMP mínimo (RFC 2408), Main Mode, sem
# payload de proposta — simplificação deliberada (o objetivo é só confirmar
# que algo fala ISAKMP na porta, não completar uma negociação). Nem toda
# implementação responde a um cabeçalho sem payload; tratado como best-effort. ---
_ISAKMP_HEADER_ONLY = (
    b"\x00\x00\x00\x00\x00\x00\x00\x01"  # initiator cookie (não-zero, "requisição")
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # responder cookie (zero — primeira mensagem)
    b"\x00"  # next payload = NONE
    b"\x10"  # versão: major=1, minor=0 (IKEv1)
    b"\x02"  # exchange type = Identity Protection (Main Mode)
    b"\x00"  # flags
    b"\x00\x00\x00\x00"  # message id = 0 (fase 1)
    b"\x00\x00\x00\x1c"  # length = 28 (só o cabeçalho)
)

#: (nome do serviço, payload) por porta UDP. Fonte única — ``UDP_PROBES`` e
#: ``UDP_SERVICE_NAMES`` são derivados daqui para nunca ficarem dessincronizados.
_UDP_SERVICES: dict[int, tuple[str, bytes]] = {
    53: ("dns", _DNS_VERSION_BIND),
    123: ("ntp", _NTP_CLIENT_REQUEST),
    137: ("netbios-ns", _NBNS_WILDCARD_NBSTAT),
    161: ("snmp", _SNMP_GET_SYSDESCR),
    500: ("isakmp", _ISAKMP_HEADER_ONLY),
    5353: ("mdns", _MDNS_SERVICES_QUERY),
}

UDP_PROBES: dict[int, bytes] = {port: payload for port, (_, payload) in _UDP_SERVICES.items()}
UDP_SERVICE_NAMES: dict[int, str] = {port: name for port, (name, _) in _UDP_SERVICES.items()}
