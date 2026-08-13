"""Interface de scanner adapters (integração real progressiva).

Cada capacidade de varredura é encapsulada num adapter que implementa esta
interface comum. Isso permite adicionar novas integrações (nmap, DNS, TLS,
CVE...) sem alterar o orquestrador, e trocar/mockar adapters por configuração.

Ver docs/scanning-engine.md. IMPORTANTE: todo adapter deve respeitar a
Política de Autorização de Alvos — nenhuma varredura fora do escopo autorizado.
"""

from __future__ import annotations

import ipaddress
import secrets
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class ScanCancelled(Exception):  # noqa: N818 — nome alinhado ao domínio (evento de cancelamento)
    """Levantada por ``ScanContext.check_cancelled`` quando o scan foi cancelado.

    Adapters de longa duração chamam ``context.check_cancelled()`` entre
    lotes de probe para abortar cooperativamente assim que possível, em vez
    de rodar até o fim ignorando o cancelamento do usuário.
    """


@dataclass
class ScanContext:
    """Contexto de execução repassado aos adapters.

    Attributes:
        scan_id: Identificador do scan em execução.
        authorized_by: Quem autorizou o scan (auditoria/autorização).
        authorization_scope: Escopo autorizado; o adapter não deve varrer
            nada fora dele.
        options: Parâmetros extras específicos do adapter (ver ``profiles.py``).
        should_abort: Callback opcional que retorna ``True`` quando o scan foi
            cancelado. Injetado pela orquestração (``tasks.run_scan``).
    """

    scan_id: str
    authorized_by: str
    authorization_scope: str
    options: dict[str, Any] = field(default_factory=dict)
    should_abort: Callable[[], bool] | None = None

    def check_cancelled(self) -> None:
        """Levanta ``ScanCancelled`` se ``should_abort`` indicar cancelamento.

        Sem efeito quando ``should_abort`` não foi injetado (ex.: chamadas
        diretas de adapter em teste) — cooperativo, não obrigatório.
        """
        if self.should_abort is not None and self.should_abort():
            raise ScanCancelled(f"Scan {self.scan_id} cancelado.")


@dataclass
class RawResult:
    """Resultado bruto produzido por um adapter, entregue ao parser.

    Attributes:
        kind: Tipo do resultado (ex.: "service", "fingerprint", "finding").
        data: Payload cru normalizado posteriormente pelo parser.
    """

    kind: str
    data: dict[str, Any]


class ScannerAdapter(ABC):
    """Contrato base para todos os adapters de varredura."""

    #: Nome único do adapter (ex.: "port-discovery").
    name: str = "base"
    #: Tipo de scan que o adapter atende: discovery | fingerprint | vulnerability.
    scan_type: str = "discovery"

    @abstractmethod
    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Executa a varredura contra ``target`` e retorna resultados brutos.

        Implementações reais entram nas próximas fases (ver roadmap). Nesta
        fase de fundação a interface existe para guiar a arquitetura.
        """
        raise NotImplementedError


class NoopAdapter(ScannerAdapter):
    """Adapter de exemplo que não realiza varredura alguma.

    Serve como referência de implementação e para testes/demonstrações sem
    tocar em alvos reais.
    """

    name = "noop"
    scan_type = "discovery"

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Retorna uma lista vazia — nenhuma varredura é executada."""
        return []


# Portas comuns inspecionadas na descoberta de serviços. Lista curta e
# conservadora — o objetivo é exposição, não varredura exaustiva.
DEFAULT_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}

CONNECT_TIMEOUT = 1.5
MAX_WORKERS = 32
BANNER_TIMEOUT = 1.5
BANNER_READ_SIZE = 512
#: "Nudges" mínimos enviados antes do recv() para protocolos que não
#: bannerizam sozinhos (ex.: Redis exige um comando antes de responder;
#: SSH/FTP/SMTP/POP3/IMAP/MySQL já enviam o banner assim que a conexão abre).
_BANNER_NUDGES: dict[int, bytes] = {6379: b"PING\r\n"}


def _resolve_ip(host: str) -> str | None:
    """Resolve um host/domínio para um IP — IPv4 ou IPv6 (None se não resolver).

    IPs literais (v4 ou v6) passam direto, sem round-trip de DNS. Quando o
    host resolve para as duas famílias, prefere IPv4 (mantém compatibilidade
    com o inventário/testes existentes); usa IPv6 quando é a única família
    disponível (host IPv6-only). ``socket.gethostbyname`` (usado antes) é
    IPv4-only e nunca enxergava registros AAAA nem aceitava um IPv6 literal.
    """
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    import socket

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return None
    addrs = [info[4][0] for info in infos]
    ipv4 = next((addr for addr in addrs if ":" not in addr), None)
    return ipv4 or (addrs[0] if addrs else None)


def _address_family(ip: str) -> int:
    """Família de socket (``AF_INET``/``AF_INET6``) para um IP literal."""
    import socket

    return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET


def _url_host(host: str) -> str:
    """Formata um host para uso em URL — IPv6 literal precisa de colchetes (RFC 3986).

    ``http://2001:db8::1:8080/`` é ambíguo (não dá pra saber onde o endereço
    termina e a porta começa); hostnames e IPv4 não precisam de tratamento.
    """
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host


class PortDiscoveryAdapter(ScannerAdapter):
    """Descobre serviços TCP expostos via connect scan (socket) com banner grab.

    Usa ``socket`` puro (TCP connect) — sem depender do binário nmap. Após
    confirmar a porta aberta, faz uma leitura curta na mesma conexão para
    capturar o banner do serviço e extrair produto/versão (``banners.py``) —
    alimenta o *technology profile* que o ``CveLookupAdapter`` correlaciona
    com CVEs na fase de vulnerabilidade. Respeita timeout e concorrência
    limitada; nenhuma técnica de evasão é empregada.
    """

    name = "port-discovery"
    scan_type = "discovery"

    def __init__(self, ports: dict[int, str] | None = None) -> None:
        #: Conjunto de portas fixo (uso avançado/testes). ``None`` = resolver
        #: dinamicamente por ``context.options["port_set"]`` a cada execução —
        #: este adapter é um singleton reaproveitado entre scans com opções
        #: diferentes (ver registry no fim do módulo).
        self._fixed_ports = ports

    def _port_set(self, options: dict[str, Any]) -> dict[int, str]:
        """Resolve o dict de portas a varrer nesta execução."""
        if self._fixed_ports is not None:
            return self._fixed_ports

        from .data.ports import TOP_100, TOP_1000

        by_name = {"top16": DEFAULT_PORTS, "top100": TOP_100, "top1000": TOP_1000}
        return by_name.get(options.get("port_set"), TOP_100)

    def _probe(self, ip: str, port: int) -> tuple[bool, bytes]:
        """TCP connect + leitura curta do banner. Retorna ``(porta_aberta, banner)``."""
        import socket

        with socket.socket(_address_family(ip), socket.SOCK_STREAM) as sock:
            sock.settimeout(CONNECT_TIMEOUT)
            if sock.connect_ex((ip, port)) != 0:
                return False, b""
            sock.settimeout(BANNER_TIMEOUT)
            nudge = _BANNER_NUDGES.get(port)
            if nudge:
                try:
                    sock.sendall(nudge)
                except OSError:
                    pass
            try:
                banner = sock.recv(BANNER_READ_SIZE)
            except OSError:
                banner = b""
            return True, banner

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Varre as portas do perfil ativo em ``target`` e retorna serviços abertos."""
        from concurrent.futures import ThreadPoolExecutor

        from .banners import parse_banner

        context.check_cancelled()
        ip = _resolve_ip(target)
        if ip is None:
            return []

        ports = self._port_set(context.options)
        results: list[RawResult] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {port: pool.submit(self._probe, ip, port) for port in ports}
            for port, future in futures.items():
                try:
                    is_open, banner = future.result()
                except OSError:
                    is_open, banner = False, b""
                if not is_open:
                    continue
                data = {
                    "host": target,
                    "ip": ip,
                    "port": port,
                    "protocol": "tcp",
                    "service_name": ports[port],
                }
                matches = parse_banner(port, banner)
                if matches:
                    banner_match = matches[0]
                    data["product"] = banner_match.get("product")
                    data["version"] = banner_match.get("version")
                    if banner_match.get("service_name"):
                        data["service_name"] = banner_match["service_name"]
                results.append(RawResult(kind="service", data=data))
        return results


class UdpProbeAdapter(ScannerAdapter):
    """Descobre serviços UDP expostos via probes leves por protocolo.

    UDP não tem handshake: a ausência de resposta pode significar tanto
    "fechado" quanto "aberto, mas o probe não bateu com o protocolo exato"
    (o ICMP port-unreachable que indicaria "fechado com certeza" nem sempre
    chega até nós). Por isso todo serviço detectado aqui carrega
    ``confidence: "low"`` na evidência — sinal de exposição, não confirmação
    definitiva. Ver ``data/udp_probes.py`` para os payloads usados.
    """

    name = "udp-probe"
    scan_type = "discovery"

    UDP_TIMEOUT = 2.0
    UDP_READ_SIZE = 512

    def __init__(self, probes: dict[int, bytes] | None = None) -> None:
        self._fixed_probes = probes

    def _probes(self) -> dict[int, bytes]:
        if self._fixed_probes is not None:
            return self._fixed_probes

        from .data.udp_probes import UDP_PROBES

        return UDP_PROBES

    def _probe_udp(self, ip: str, port: int, payload: bytes) -> bool:
        """Envia o payload e aguarda qualquer resposta. True se algo respondeu."""
        import socket

        with socket.socket(_address_family(ip), socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.UDP_TIMEOUT)
            try:
                sock.sendto(payload, (ip, port))
                sock.recv(self.UDP_READ_SIZE)
                return True
            except OSError:
                return False

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Envia os probes UDP conhecidos e retorna as portas que responderam."""
        from concurrent.futures import ThreadPoolExecutor

        from .data.udp_probes import UDP_SERVICE_NAMES

        context.check_cancelled()
        ip = _resolve_ip(target)
        if ip is None:
            return []

        probes = self._probes()
        results: list[RawResult] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                port: pool.submit(self._probe_udp, ip, port, payload)
                for port, payload in probes.items()
            }
            for port, future in futures.items():
                try:
                    responded = future.result()
                except OSError:
                    responded = False
                if responded:
                    results.append(
                        RawResult(
                            kind="service",
                            data={
                                "host": target,
                                "ip": ip,
                                "port": port,
                                "protocol": "udp",
                                "service_name": UDP_SERVICE_NAMES.get(port, "unknown"),
                            },
                        )
                    )
        return results


class DnsAdapter(ScannerAdapter):
    """Descobre registros DNS de um alvo (A/AAAA/MX/NS/TXT) via dnspython."""

    name = "dns"
    scan_type = "discovery"
    RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Consulta registros DNS do alvo e retorna hosts/registros."""
        import dns.resolver

        context.check_cancelled()
        results: list[RawResult] = []
        for rtype in self.RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(target, rtype)
            except Exception:  # noqa: BLE001 — DNS lança várias exceções específicas
                continue
            for rdata in answers:
                value = rdata.to_text()
                if rtype in {"A", "AAAA"}:
                    results.append(
                        RawResult(
                            kind="host",
                            data={"hostname": target, "ip": value, "domain": target},
                        )
                    )
                else:
                    results.append(
                        RawResult(
                            kind="dns_record",
                            data={"domain": target, "record_type": rtype, "value": value},
                        )
                    )
        return results


#: Registros DNS não-host retornados por AXFR que viram ``kind="dns_record"``
#: (A/AAAA viram ``kind="host"`` — mesma convenção de ``DnsAdapter``).
_AXFR_NON_HOST_TYPES = {"MX", "NS", "TXT", "SOA", "SRV", "CNAME", "CAA", "PTR"}
AXFR_TIMEOUT = 10.0


def _is_domain_target(target: str) -> bool:
    """True se ``target`` for um domínio (não IP/CIDR/host único sem ponto)."""
    from .validators import InvalidTarget, classify_target

    try:
        return classify_target(target) == "domain"
    except InvalidTarget:
        return False


class SubdomainAdapter(ScannerAdapter):
    """Enumera subdomínios via wordlist e Certificate Transparency (crt.sh).

    Duas fontes: (a) força bruta de prefixos comuns (``data/subdomains.py``)
    resolvidos via DNS; (b) consulta ao crt.sh — nomes que já apareceram em
    certificados emitidos para o domínio, sem precisar adivinhar. Cada
    candidato é **revalidado contra o escopo autorizado antes de qualquer
    resolução DNS** — um nome descoberto via CT log público (fora do
    controle do alvo) nunca é tocado se cair fora do escopo.
    """

    name = "subdomain-enum"
    scan_type = "discovery"

    CRTSH_TIMEOUT = 10.0
    CRTSH_MAX_CANDIDATES = 500

    def _resolve(self, hostname: str) -> str | None:
        """Resolve um hostname para IP (v4 ou v6). ``None`` se não resolver."""
        return _resolve_ip(hostname)

    def _fetch_crtsh(self, domain: str) -> list[dict[str, Any]]:
        """Consulta o crt.sh por certificados emitidos para ``*.<domain>``."""
        import requests
        from requests.exceptions import RequestException

        try:
            response = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=self.CRTSH_TIMEOUT,
                headers={"User-Agent": "Byakugan-Scanner/0.1 (authorized assessment)"},
            )
            response.raise_for_status()
            return response.json()
        except (RequestException, ValueError):
            return []

    def _candidates_from_wordlist(self, domain: str, wordlist_size: int) -> set[str]:
        from .data.subdomains import COMMON_SUBDOMAINS

        prefixes = COMMON_SUBDOMAINS[: max(wordlist_size, 0)]
        return {f"{prefix}.{domain}" for prefix in prefixes}

    def _candidates_from_crtsh(self, domain: str) -> set[str]:
        candidates: set[str] = set()
        for entry in self._fetch_crtsh(domain):
            for raw_name in str(entry.get("name_value", "")).splitlines():
                name = raw_name.strip().lower().removeprefix("*.")
                if name and (name == domain or name.endswith(f".{domain}")):
                    candidates.add(name)
                if len(candidates) >= self.CRTSH_MAX_CANDIDATES:
                    return candidates
        return candidates

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Enumera subdomínios de ``target`` e retorna os que resolvem, dentro do escopo."""
        from concurrent.futures import ThreadPoolExecutor

        from .authorization import is_target_in_scope

        context.check_cancelled()
        if not _is_domain_target(target):
            return []  # enumeração de subdomínio só faz sentido para um domínio

        wordlist_size = int(context.options.get("wordlist_size", 200))
        candidates = self._candidates_from_wordlist(
            target, wordlist_size
        ) | self._candidates_from_crtsh(target)
        candidates.discard(target)  # o próprio domínio não é um "subdomínio"

        in_scope = [c for c in candidates if is_target_in_scope(c, context.authorization_scope)]

        max_workers = int(context.options.get("max_workers", MAX_WORKERS))
        results: list[RawResult] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._resolve, host): host for host in in_scope}
            for future in futures:
                host = futures[future]
                try:
                    ip = future.result()
                except OSError:
                    ip = None
                if ip:
                    results.append(
                        RawResult(kind="host", data={"hostname": host, "ip": ip, "domain": target})
                    )
        return results


class ZoneTransferAdapter(ScannerAdapter):
    """Tenta transferência de zona (AXFR) contra os nameservers do domínio.

    AXFR mal configurado (permitindo transferência para qualquer cliente,
    não só servidores secundários autorizados) vaza o inventário completo de
    hosts internos do domínio — uma das exposições de DNS mais graves e
    clássicas. A operação em si é somente leitura (RFC 5936: AXFR é uma
    consulta, não uma escrita) — não altera nada no nameserver.
    """

    name = "zone-transfer"
    scan_type = "discovery"

    def _nameservers(self, domain: str) -> list[str]:
        """Resolve os nameservers autoritativos do domínio."""
        import dns.resolver

        try:
            answers = dns.resolver.resolve(domain, "NS")
        except Exception:  # noqa: BLE001 — DNS lança várias exceções específicas
            return []
        return [str(rdata.target).rstrip(".") for rdata in answers]

    def _axfr(self, nameserver_ip: str, domain: str) -> list[tuple[str, str, str]]:
        """Tenta AXFR contra o IP do NS. Lista de ``(nome, tipo, valor)`` se aceito.

        ``relativize=False`` em ambas as chamadas (precisam combinar, ver
        docstring de ``dns.query.xfr``): sem isso, nomes referenciados DENTRO
        de rdata (alvo de NS/MX, não só a chave do nó) saem relativizados à
        origem da zona — ex.: um MX para "mail.example.com." apareceria como
        apenas "mail", perdendo o domínio. Com ``relativize=False`` toda
        saída de ``.to_text()`` é o nome absoluto, correto para evidência.
        """
        import dns.query
        import dns.rdatatype
        import dns.zone

        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(
                    nameserver_ip,
                    domain,
                    timeout=AXFR_TIMEOUT,
                    lifetime=AXFR_TIMEOUT,
                    relativize=False,
                ),
                relativize=False,
            )
        except Exception:  # noqa: BLE001 — AXFR recusado/timeout/erro de protocolo, etc.
            return []

        records: list[tuple[str, str, str]] = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                rtype = dns.rdatatype.to_text(rdataset.rdtype)
                for rdata in rdataset:
                    records.append((str(name).rstrip("."), rtype, rdata.to_text()))
        return records

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Tenta AXFR em cada NS do domínio e retorna o que vazar, se aceito."""
        context.check_cancelled()
        if not _is_domain_target(target):
            return []

        results: list[RawResult] = []
        for nameserver in self._nameservers(target):
            context.check_cancelled()
            ns_ip = _resolve_ip(nameserver)
            if ns_ip is None:
                continue
            records = self._axfr(ns_ip, target)
            if not records:
                continue

            results.append(
                RawResult(
                    kind="vulnerability",
                    data={
                        "domain": target,
                        "hostname": target,
                        "title": f"Transferência de zona (AXFR) permitida em {nameserver}",
                        "severity": "high",
                        "category": "dns",
                        "description": (
                            f"O nameserver {nameserver} aceitou uma transferência de "
                            f"zona (AXFR) completa para '{target}', vazando "
                            f"{len(records)} registro(s) — normalmente restrito a "
                            "servidores DNS secundários autorizados."
                        ),
                        "evidence": (
                            f"AXFR contra {nameserver} ({ns_ip}) retornou "
                            f"{len(records)} registro(s) da zona {target}."
                        ),
                        "recommendation": (
                            "Restringir AXFR (allow-transfer) apenas aos IPs dos "
                            "servidores DNS secundários autorizados."
                        ),
                    },
                )
            )

            for name, rtype, value in records:
                # _axfr já devolve nomes absolutos (relativize=False) — o
                # nó do ápice da zona vem como o próprio domínio (ex.:
                # "example.com"), sem necessidade de caso especial aqui.
                if rtype in {"A", "AAAA"}:
                    results.append(
                        RawResult(
                            kind="host",
                            data={"hostname": name, "ip": value, "domain": target},
                        )
                    )
                elif rtype in _AXFR_NON_HOST_TYPES:
                    results.append(
                        RawResult(
                            kind="dns_record",
                            data={"domain": target, "record_type": rtype, "value": value},
                        )
                    )
        return results


#: Seletores DKIM comuns testados. O seletor real é arbitrário (definido
#: pelo provedor de e-mail) — não há como descobri-lo com certeza sem acesso
#: à configuração; esta lista cobre os padrões mais frequentes na prática.
COMMON_DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "dkim",
    "smtp",
)


class EmailSecurityAdapter(ScannerAdapter):
    """Avalia a postura de segurança de e-mail do domínio (SPF/DMARC/DKIM).

    Consulta os TXT records relevantes (SPF no próprio domínio, DMARC em
    ``_dmarc.<domínio>``, DKIM nos seletores comuns) e delega o julgamento a
    ``dns_analysis.analyze_email_security`` — mesmo padrão dos demais
    adapters de vulnerabilidade sem CVE (TLS, credenciais).
    """

    name = "email-security"
    scan_type = "discovery"

    def _query_txt(self, name: str) -> list[str]:
        """Consulta TXT records de ``name``, concatenando strings fragmentadas."""
        import dns.resolver

        try:
            answers = dns.resolver.resolve(name, "TXT")
        except Exception:  # noqa: BLE001 — DNS lança várias exceções específicas
            return []
        records = []
        for rdata in answers:
            strings = getattr(rdata, "strings", None)
            if strings is None:
                records.append(rdata.to_text().strip('"'))
                continue
            text = "".join(s.decode() if isinstance(s, bytes) else s for s in strings)
            records.append(text)
        return records

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Avalia SPF/DMARC/DKIM do domínio e retorna os findings encontrados."""
        from . import dns_analysis

        context.check_cancelled()
        if not _is_domain_target(target):
            return []

        spf_records = [
            r for r in self._query_txt(target) if r.lower().startswith(dns_analysis.SPF_PREFIX)
        ]
        dmarc_records = [
            r
            for r in self._query_txt(f"_dmarc.{target}")
            if r.lower().startswith(dns_analysis.DMARC_PREFIX)
        ]
        dkim_selectors_found = [
            selector
            for selector in COMMON_DKIM_SELECTORS
            if self._query_txt(f"{selector}._domainkey.{target}")
        ]

        findings = dns_analysis.analyze_email_security(
            spf_records=spf_records,
            dmarc_records=dmarc_records,
            dkim_selectors_found=dkim_selectors_found,
            domain=target,
        )
        return [
            RawResult(kind="vulnerability", data={**finding, "domain": target, "hostname": target})
            for finding in findings
        ]


# Portas HTTP(S) comuns inspecionadas no fingerprinting web.
HTTP_PORTS: dict[int, str] = {80: "http", 8080: "http", 443: "https", 8443: "https"}

HTTP_TIMEOUT = 4.0
# Limite de corpo lido para casar assinaturas — evita baixar páginas enormes.
MAX_BODY_BYTES = 200_000


class HttpFingerprintAdapter(ScannerAdapter):
    """Identifica tecnologias web via HTTP (headers + assinaturas no HTML).

    Faz uma requisição GET às portas HTTP(S) comuns do alvo e deriva servidor
    web, linguagem, framework, CMS e tecnologia de frontend a partir dos headers
    (``Server``, ``X-Powered-By``, cookies) e de padrões no corpo. Não emprega
    técnica de evasão; é uma inspeção de exposição de serviços autorizados.
    """

    name = "http-fingerprint"
    scan_type = "fingerprint"

    def __init__(self, ports: dict[int, str] | None = None) -> None:
        self.ports = ports or HTTP_PORTS

    def _fetch(self, url: str) -> tuple[dict[str, str], str] | None:
        """Faz um GET e retorna (headers, corpo). None em qualquer falha."""
        import requests
        from requests.exceptions import RequestException

        try:
            # verify=False: laboratórios usam certificados self-signed. Não é
            # evasão — apenas evita abortar o fingerprint por cadeia não confiável.
            response = requests.get(
                url,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                verify=False,
                stream=True,
                headers={"User-Agent": "Byakugan-Scanner/0.1 (authorized assessment)"},
            )
            body = response.raw.read(MAX_BODY_BYTES, decode_content=True) or b""
            headers = {k: v for k, v in response.headers.items()}
            return headers, body.decode("utf-8", errors="ignore")
        except RequestException:
            return None
        except OSError:
            return None

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Faz fingerprint HTTP do alvo e retorna tecnologias identificadas."""
        import urllib3

        # Silencia o aviso de verificação TLS desabilitada (ver _fetch).
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        from .signatures import fingerprint_http

        context.check_cancelled()
        ip = _resolve_ip(target)
        results: list[RawResult] = []
        seen: set[tuple[str, str]] = set()

        for port, scheme in self.ports.items():
            fetched = self._fetch(f"{scheme}://{_url_host(target)}:{port}/")
            if fetched is None:
                continue
            headers, body = fetched
            for tech in fingerprint_http(headers, body):
                key = (tech["category"], tech["name"].lower())
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    RawResult(
                        kind="technology",
                        data={**tech, "host": target, "hostname": target, "ip": ip, "port": port},
                    )
                )
        return results


# Protocolos TLS considerados obsoletos (evidência de exposição).
DEPRECATED_TLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
TLS_PORT = 443
TLS_TIMEOUT = 4.0


#: Versões de protocolo que ``_probe_versions`` tenta forçar explicitamente.
#: SSLv2/SSLv3 não entram aqui: o OpenSSL do sistema normalmente as remove em
#: tempo de compilação (o Python ``ssl`` nem oferece ``TLSVersion.SSLv3`` de
#: forma confiável) — na prática, o que este probe consegue mesmo confirmar é
#: TLSv1.0 a TLSv1.3. ``DEPRECATED_TLS`` continua cobrindo SSLv2/v3 para o
#: caso (raro) de um ambiente antigo em que a negociação padrão os exponha.
_PROBEABLE_VERSION_LABELS = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")


class TlsAdapter(ScannerAdapter):
    """Analisa TLS e certificado do serviço HTTPS do alvo.

    Usa ``ssl``/``socket`` (stdlib) para negociação e enumeração de
    protocolos, e ``cryptography`` para decodificar o certificado (DER) —
    única dependência externa do módulo, adicionada nesta fase. Reporta a
    versão TLS negociada como tecnologia (comportamento já existente) **e**
    findings de vulnerabilidade (protocolo/cipher fraco, certificado
    expirado/self-signed/hostname-mismatch/chave-ou-assinatura fraca —
    ``tls_analysis.analyze_tls``).
    """

    name = "tls"
    scan_type = "fingerprint"

    def __init__(self, port: int = TLS_PORT) -> None:
        self.port = port

    def _probe_tls(self, host: str) -> tuple[str, str, int] | None:
        """Negocia TLS (config padrão) e retorna (versão, cipher, bits)."""
        import socket
        import ssl

        ctx = ssl.create_default_context()
        # Aceita self-signed (comum em lab): o objetivo é inspecionar o protocolo,
        # não validar a cadeia de confiança.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, self.port), timeout=TLS_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version() or "unknown"
                    cipher = ssock.cipher() or ("unknown", "", 0)
                    return version, cipher[0], int(cipher[2] or 0)
        except (OSError, ssl.SSLError):
            return None

    def _probe_versions(self, host: str) -> list[str]:
        """Força cada versão de protocolo e retorna as que o servidor aceitou."""
        import socket
        import ssl

        version_enum = {
            "TLSv1": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }
        supported: list[str] = []
        for label in _PROBEABLE_VERSION_LABELS:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ctx.maximum_version = version_enum[label]
            except ValueError:
                continue  # versão não suportada pelo OpenSSL local
            try:
                with socket.create_connection((host, self.port), timeout=TLS_TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        supported.append(label)
            except (OSError, ssl.SSLError):
                continue
        return supported

    def _get_cert(self, host: str) -> dict[str, Any] | None:
        """Obtém o certificado do serviço e extrai os campos usados por ``analyze_tls``."""
        import socket
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, self.port), timeout=TLS_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            return None
        if not der:
            return None

        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

        cert = x509.load_der_x509_certificate(der)

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = list(san_ext.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            san = []

        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type, key_size = "RSA", public_key.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            key_type, key_size = "DSA", public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type, key_size = "EC", public_key.curve.key_size
        else:
            key_type, key_size = type(public_key).__name__, None

        signature_hash = cert.signature_hash_algorithm
        return {
            "not_valid_before": cert.not_valid_before_utc,
            "not_valid_after": cert.not_valid_after_utc,
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "san": san,
            "key_type": key_type,
            "key_size": key_size,
            "signature_algorithm": signature_hash.name if signature_hash else "",
        }

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Faz o probe TLS/certificado do alvo e retorna tecnologia + findings."""
        from django.utils import timezone as django_timezone

        from .tls_analysis import analyze_tls

        context.check_cancelled()
        probed = self._probe_tls(target)
        if probed is None:
            return []
        version, cipher, bits = probed
        ip = _resolve_ip(target)
        deprecated = version in DEPRECATED_TLS
        evidence = f"cipher={cipher}, bits={bits}"
        if deprecated:
            evidence += " (protocolo obsoleto)"

        results = [
            RawResult(
                kind="technology",
                data={
                    "category": "tls",
                    "name": "TLS",
                    "version": version,
                    "source": "tls",
                    "evidence": evidence,
                    "confidence": "high",
                    "host": target,
                    "hostname": target,
                    "ip": ip,
                    "port": self.port,
                },
            )
        ]

        supported_versions = self._probe_versions(target)
        cert_fields = self._get_cert(target)
        findings = analyze_tls(
            supported_versions=supported_versions,
            cipher=(cipher, bits),
            cert_fields=cert_fields,
            hostname=target,
            now=django_timezone.now(),
        )
        for finding in findings:
            results.append(
                RawResult(
                    kind="vulnerability",
                    data={**finding, "host": target, "hostname": target, "ip": ip},
                )
            )
        return results


# Máximo de CVEs considerados por produto/versão — evita flooding de findings
# a partir de um único match amplo de palavra-chave na NVD.
NVD_MAX_RESULTS = 5
NVD_TIMEOUT = 10.0

#: Categorias de ``Technology`` que identificam um PRODUTO de software real
#: (nome+versão correlacionáveis a CVE). ``tls`` fica de fora de propósito:
#: é o protocolo negociado (``TlsAdapter`` grava ``Technology(category="tls",
#: name="TLS", version="TLSv1.3")``), não um produto — tratá-lo como tal faz
#: o CPE match falhar (não existe fornecedor "tls") e cair no fallback
#: ``keywordSearch="TLS TLSv1.3"``, que casa qualquer CVE cujo texto apenas
#: MENCIONE TLS 1.3 como pré-requisito (ex.: CVEs específicas de wolfSSL,
#: Apache mod_ssl, F5 BIG-IP ou OpenSSL que citam "TLS 1.3 enabled" nas
#: condições) — um falso positivo grave, já que o scanner nunca identificou
#: a implementação real. ``other`` também fica de fora por não garantir que
#: ``name``/``version`` sejam um produto identificável.
PRODUCT_TECHNOLOGY_CATEGORIES = frozenset(
    {"os", "web-server", "framework", "language", "frontend", "cms", "database"}
)


class CveLookupAdapter(ScannerAdapter):
    """Correlaciona produtos/versões já identificados com CVEs conhecidos (NVD).

    Diferente dos demais adapters, não varre a rede diretamente: lê o
    *technology profile* já persistido do ativo (``Service.product``/``version``
    e ``Technology.name``/``version``) e consulta a API NVD CVE 2.0 por
    palavra-chave para cada produto/versão único. Por isso só produz resultados
    úteis quando executado **depois** de um discovery/fingerprint sobre o mesmo
    alvo — a orquestração (``tasks.run_scan``) garante essa ordem em scans
    ``full``, persistindo o profile antes de rodar este adapter.

    Respeita rate limit da NVD (`NVD_REQUEST_DELAY_SECONDS`) e nunca deriva
    técnicas de exploração — apenas correlação informativa de versão × CVE.
    """

    name = "cve-lookup"
    scan_type = "vulnerability"

    def __init__(
        self,
        *,
        request_delay: float | None = None,
        max_results: int = NVD_MAX_RESULTS,
    ) -> None:
        from django.conf import settings

        self.base_url = settings.NVD_API_BASE_URL
        self.api_key = settings.NVD_API_KEY
        self.request_delay = (
            settings.NVD_REQUEST_DELAY_SECONDS if request_delay is None else request_delay
        )
        self.max_results = max_results

    def _query_nvd(
        self, *, cpe_match: str | None = None, keyword: str | None = None
    ) -> list[dict[str, Any]]:
        """Busca CVEs na NVD por CPE (``virtualMatchString``) ou por palavra-chave.

        Informar exatamente um dos dois — CPE é mais preciso (casa contra o
        dicionário oficial de produtos/versões da NVD); ``keywordSearch`` é
        busca de texto livre, usada como fallback quando a busca por CPE não
        retorna nada (produto não catalogado no dicionário CPE, versão
        formatada de forma não-padrão etc.). Lista vazia em qualquer falha.
        """
        import requests
        from requests.exceptions import RequestException

        params: dict[str, Any] = {"resultsPerPage": self.max_results}
        if cpe_match:
            params["virtualMatchString"] = cpe_match
        elif keyword:
            params["keywordSearch"] = keyword
        else:
            return []

        headers = {"User-Agent": "Byakugan-Scanner/0.1 (authorized assessment)"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=NVD_TIMEOUT,
            )
            response.raise_for_status()
            return response.json().get("vulnerabilities", [])
        except (RequestException, ValueError):
            return []

    @staticmethod
    def _collect_products(asset: Any) -> list[tuple[str, str, str, int | None]]:
        """Reúne pares (produto, versão) únicos do ativo — serviços e tecnologias.

        Tecnologias fora de ``PRODUCT_TECHNOLOGY_CATEGORIES`` (ex.: ``tls``, o
        protocolo negociado, não um produto) são ignoradas — nunca viram
        candidato a lookup de CVE.
        """
        products: list[tuple[str, str, str, int | None]] = []
        seen: set[tuple[str, str]] = set()

        for service in asset.services.all():
            if not service.product or not service.version:
                continue
            key = (service.product.lower(), service.version)
            if key not in seen:
                seen.add(key)
                products.append((service.product, service.version, "service", service.port))

        for tech in asset.technologies.all():
            if tech.category not in PRODUCT_TECHNOLOGY_CATEGORIES:
                continue
            if not tech.name or not tech.version:
                continue
            key = (tech.name.lower(), tech.version)
            if key not in seen:
                seen.add(key)
                products.append((tech.name, tech.version, "technology", None))

        return products

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Correlaciona o technology profile do ativo com CVEs da NVD."""
        from django.db.models import Q

        from apps.assets.models import Asset

        from .cve import build_cpe_match, map_cve_item

        context.check_cancelled()
        asset = Asset.objects.filter(Q(ip=target) | Q(hostname=target) | Q(domain=target)).first()
        if asset is None:
            return []

        products = self._collect_products(asset)
        results: list[RawResult] = []

        for index, (name, version, source, port) in enumerate(products):
            if index > 0 and self.request_delay > 0:
                time.sleep(self.request_delay)

            cpe_match = build_cpe_match(name, version)
            items = self._query_nvd(cpe_match=cpe_match)
            search_note = f'NVD virtualMatchString="{cpe_match}".'
            if not items:
                # CPE não achou nada (produto fora do dicionário CPE, versão em
                # formato não-padrão etc.) — cai para busca por texto livre.
                items = self._query_nvd(keyword=f"{name} {version}")
                search_note = f'NVD keywordSearch="{name} {version}".'

            for item in items:
                mapped = map_cve_item(item)
                if mapped is None:
                    continue
                port_note = f" (porta {port})" if port else ""
                evidence = f"{name} {version} identificado via {source}{port_note}. " + search_note
                recommendation = (
                    f"Atualizar {name} para uma versão corrigida. Consultar as "
                    f"referências do CVE {mapped['cve']} para detalhes de mitigação."
                )
                results.append(
                    RawResult(
                        kind="vulnerability",
                        data={
                            **mapped,
                            "title": f"{mapped['cve']} em {name} {version}",
                            "category": "software",
                            "evidence": evidence,
                            "recommendation": recommendation,
                            "asset_id": str(asset.id),
                            "product": name,
                            "product_version": version,
                        },
                    )
                )
        return results


#: Portas com verificações de credencial/acesso não autenticado conhecidas.
DEFAULT_CREDS_TIMEOUT = 4.0
FTP_PORT = 21
REDIS_PORT = 6379
ELASTICSEARCH_PORT = 9200
#: Portas HTTP/admin comuns onde vale checar Basic Auth default e o
#: Spring Boot Actuator exposto — não é uma varredura de path completa (isso
#: é do ``WebScanAdapter``, fase seguinte), só os dois checks de credencial.
HTTP_ADMIN_PORTS = {80, 443, 8080, 8081, 8161, 8443, 9090}
ACTUATOR_HEALTH_PATH = "/actuator/health"


class DefaultCredsAdapter(ScannerAdapter):
    """Verifica credenciais default/acesso não autenticado em serviços conhecidos.

    Detecção não-destrutiva: uma única tentativa por credencial/serviço, sem
    força bruta e sem lockout. Só roda em intensidade ``aggressive`` (opt-in
    explícito do usuário) e **revalida o alvo contra o escopo autorizado**
    antes de tentar qualquer credencial — camada extra de segurança para o
    check mais sensível do motor. Só considera portas já confirmadas abertas
    pela fase de discovery deste mesmo scan (não abre conexões "às cegas").
    """

    name = "default-creds"
    scan_type = "vulnerability"

    def _try_login(self, kind: str, host: str, port: int) -> tuple[bool, str] | None:
        """Executa uma verificação de acesso. ``(sucesso, evidência)`` ou ``None``."""
        checks = {
            "ftp-anonymous": self._check_ftp_anonymous,
            "redis-noauth": self._check_redis_noauth,
            "elasticsearch-open": self._check_elasticsearch_open,
            "http-basic-default": self._check_http_basic_default,
            "actuator-exposed": self._check_actuator_exposed,
        }
        check = checks.get(kind)
        return check(host, port) if check else None

    def _check_ftp_anonymous(self, host: str, port: int) -> tuple[bool, str]:
        import ftplib

        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=DEFAULT_CREDS_TIMEOUT)
            ftp.login("anonymous", "byakugan@scan.local")
            ftp.quit()
            return True, "Login FTP anônimo aceito (usuário 'anonymous')."
        except Exception:  # noqa: BLE001 — ftplib levanta várias exceções específicas
            return False, ""

    def _check_redis_noauth(self, host: str, port: int) -> tuple[bool, str]:
        import socket

        try:
            with socket.create_connection((host, port), timeout=DEFAULT_CREDS_TIMEOUT) as sock:
                sock.sendall(b"PING\r\n")
                response = sock.recv(64)
            if response.startswith(b"+PONG"):
                return True, "Redis respondeu a PING sem autenticação (requirepass não definido)."
            return False, ""
        except OSError:
            return False, ""

    def _check_elasticsearch_open(self, host: str, port: int) -> tuple[bool, str]:
        import requests
        from requests.exceptions import RequestException

        try:
            response = requests.get(
                f"http://{_url_host(host)}:{port}/",
                timeout=DEFAULT_CREDS_TIMEOUT,
                headers={"User-Agent": "Byakugan-Scanner/0.1 (authorized assessment)"},
            )
        except RequestException:
            return False, ""
        if response.status_code == 200 and "cluster_name" in response.text:
            return True, "Elasticsearch acessível sem autenticação (raiz expõe cluster_name)."
        return False, ""

    def _check_http_basic_default(self, host: str, port: int) -> tuple[bool, str]:
        import requests
        from requests.exceptions import RequestException

        from .data.default_creds import HTTP_BASIC_CREDS

        url = f"http://{_url_host(host)}:{port}/"
        try:
            probe = requests.get(url, timeout=DEFAULT_CREDS_TIMEOUT)
        except RequestException:
            return False, ""
        if (
            probe.status_code != 401
            or "basic" not in probe.headers.get("WWW-Authenticate", "").lower()
        ):
            return False, ""  # não usa HTTP Basic — nada a testar aqui

        for username, password in HTTP_BASIC_CREDS:
            try:
                attempt = requests.get(
                    url, auth=(username, password), timeout=DEFAULT_CREDS_TIMEOUT
                )
            except RequestException:
                continue
            if attempt.status_code != 401:
                shown_password = password or "(vazia)"
                return (
                    True,
                    f"Credencial default aceita via HTTP Basic: {username}:{shown_password}.",
                )
        return False, ""

    def _check_actuator_exposed(self, host: str, port: int) -> tuple[bool, str]:
        import requests
        from requests.exceptions import RequestException

        try:
            response = requests.get(
                f"http://{_url_host(host)}:{port}{ACTUATOR_HEALTH_PATH}",
                timeout=DEFAULT_CREDS_TIMEOUT,
            )
        except RequestException:
            return False, ""
        if response.status_code == 200 and '"status"' in response.text:
            return True, f"Spring Boot Actuator exposto sem autenticação em {ACTUATOR_HEALTH_PATH}."
        return False, ""

    def _finding(self, asset_id: str, port: int, evidence: str) -> RawResult:
        return RawResult(
            kind="vulnerability",
            data={
                "asset_id": asset_id,
                "title": f"Serviço em :{port} acessível sem autenticação adequada",
                "severity": "high",
                "category": "credential",
                "description": (
                    f"O serviço exposto na porta {port} aceita uma credencial "
                    "padrão ou não exige autenticação."
                ),
                "evidence": evidence,
                "recommendation": (
                    "Definir uma senha forte/única, desabilitar acesso anônimo e "
                    "restringir o acesso à rede autorizada."
                ),
            },
        )

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Testa credenciais default nas portas já descobertas abertas do alvo."""
        from django.db.models import Q

        from apps.assets.models import Asset

        from .authorization import is_target_in_scope

        context.check_cancelled()
        if context.options.get("intensity") != "aggressive":
            return []
        if not is_target_in_scope(target, context.authorization_scope):
            return []  # defesa extra: nunca testa credenciais fora do escopo

        asset = Asset.objects.filter(Q(ip=target) | Q(hostname=target) | Q(domain=target)).first()
        if asset is None:
            return []

        open_ports = set(asset.services.values_list("port", flat=True))
        results: list[RawResult] = []

        checks: list[tuple[int, str]] = []
        if FTP_PORT in open_ports:
            checks.append((FTP_PORT, "ftp-anonymous"))
        if REDIS_PORT in open_ports:
            checks.append((REDIS_PORT, "redis-noauth"))
        if ELASTICSEARCH_PORT in open_ports:
            checks.append((ELASTICSEARCH_PORT, "elasticsearch-open"))
        for http_port in sorted(open_ports & HTTP_ADMIN_PORTS):
            checks.append((http_port, "http-basic-default"))
            checks.append((http_port, "actuator-exposed"))

        for port, kind in checks:
            outcome = self._try_login(kind, target, port)
            if outcome is None:
                continue
            success, evidence = outcome
            if success:
                results.append(self._finding(str(asset.id), port, evidence))

        return results


#: Portas HTTP(S) testadas — mesmo conjunto de ``HttpFingerprintAdapter``.
WEB_SCAN_PORTS: dict[int, str] = {80: "http", 8080: "http", 443: "https", 8443: "https"}
WEB_FETCH_TIMEOUT = 5.0
WEB_MAX_BODY_CHARS = 200_000
#: Domínio reservado (RFC 2606, nunca resolve) usado para testar CORS.
CORS_PROBE_ORIGIN = "https://byakugan-cors-probe.invalid"
#: Máximo de pontos de injeção (url, parâmetro) testados por origem — cada
#: um gera várias requisições (7 checks + booleana + eventualmente time-based);
#: sem este teto, um site com muitos parâmetros tornaria o scan impraticável.
MAX_INJECTION_POINTS = 15


class WebScanAdapter(ScannerAdapter):
    """Orquestra web application active testing: crawl → passive → exposure → methods → injection.

    Único ponto de entrada para todo o teste ativo de aplicação web da Fase
    4 — o crawl é feito uma vez por origem e reaproveitado por todas as
    checagens. Cada porta HTTP(S) comum aberta é tratada como uma origem
    independente. Tudo não-destrutivo: só GET/OPTIONS/TRACE, marcadores
    inertes em vez de payloads executáveis (``web/injection.py``), sem
    escrita/upload/delete — ver docstrings de cada submódulo em ``web/``
    para o raciocínio de segurança de cada probe.
    """

    name = "web-scan"
    scan_type = "vulnerability"

    def _fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> tuple[int, dict[str, str], str, list[dict[str, Any]], float] | None:
        """Seam de rede único do adapter: ``(status, headers, corpo, cookies, tempo_decorrido)``.

        Cookies vêm de ``response.cookies`` (não de ``dict(response.headers)``,
        que concatena múltiplos ``Set-Cookie`` numa única string e perde a
        separação entre cookies — confirmado empiricamente contra um servidor
        HTTP real antes de adotar esta abordagem).
        """
        import requests
        from requests.exceptions import RequestException

        req_headers = {"User-Agent": "Byakugan-Scanner/0.1 (authorized assessment)"}
        if headers:
            req_headers.update(headers)
        try:
            response = requests.request(
                method,
                url,
                timeout=WEB_FETCH_TIMEOUT,
                allow_redirects=allow_redirects,
                verify=False,
                headers=req_headers,
            )
        except (RequestException, OSError):
            return None

        cookies = [
            {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly")
                or cookie.has_nonstandard_attr("httponly"),
                "samesite": cookie.get_nonstandard_attr("SameSite")
                or cookie.get_nonstandard_attr("samesite"),
            }
            for cookie in response.cookies
        ]
        body = response.text[:WEB_MAX_BODY_CHARS] if response.text else ""
        return (
            response.status_code,
            dict(response.headers),
            body,
            cookies,
            response.elapsed.total_seconds(),
        )

    def _make_finding(self, data: dict[str, Any], *, target: str, ip: str | None) -> RawResult:
        return RawResult(
            kind="vulnerability",
            data={**data, "host": target, "hostname": target, "ip": ip},
        )

    def _collect_injection_points(
        self, crawl_result: Any, base_url: str
    ) -> list[tuple[str, str, str]]:
        """Deriva pares únicos ``(url, parâmetro, valor_original)`` a testar.

        Fontes: query strings já presentes nas páginas rastreadas, e
        formulários **GET** (formulários POST não são testados ativamente —
        submetê-los poderia ter efeito colateral no alvo, o que violaria o
        princípio de não-destrutividade). Deduplicado por (path sem query,
        parâmetro) — a mesma paginação em páginas diferentes não é retestada.
        """
        from urllib.parse import urlencode, urlsplit

        from .web.crawler import extract_query_params

        seen: set[tuple[str, str]] = set()
        points: list[tuple[str, str, str]] = []

        for page in crawl_result.pages:
            params = extract_query_params(page.url)
            if not params:
                continue
            from urllib.parse import parse_qsl

            query_pairs = dict(parse_qsl(urlsplit(page.url).query, keep_blank_values=True))
            path_key = urlsplit(page.url)._replace(query="").geturl()
            for param in params:
                key = (path_key, param)
                if key in seen:
                    continue
                seen.add(key)
                points.append((page.url, param, query_pairs.get(param, "")))

        for form in crawl_result.forms:
            if form["method"] != "GET" or not form["inputs"]:
                continue
            path_key = urlsplit(form["action"])._replace(query="").geturl()
            for input_name in form["inputs"]:
                key = (path_key, input_name)
                if key in seen:
                    continue
                seen.add(key)
                blank_query = urlencode(dict.fromkeys(form["inputs"], ""))
                form_url = f"{form['action']}?{blank_query}"
                points.append((form_url, input_name, ""))

        return points

    def _run_passive_and_methods(
        self, base_url: str, target: str, ip: str | None, is_https: bool
    ) -> list[RawResult]:
        from . import web

        results: list[RawResult] = []
        base_probed = self._fetch(base_url)
        if base_probed is None:
            return results
        status, headers, body, cookies, _ = base_probed

        for finding in web.passive.analyze_security_headers(headers, is_https=is_https):
            results.append(self._make_finding(finding, target=target, ip=ip))
        for finding in web.passive.analyze_cookies(cookies, is_https=is_https):
            results.append(self._make_finding(finding, target=target, ip=ip))
        listing_finding = web.passive.analyze_directory_listing(base_url, body)
        if listing_finding:
            results.append(self._make_finding(listing_finding, target=target, ip=ip))

        cors_probed = self._fetch(base_url, headers={"Origin": CORS_PROBE_ORIGIN})
        if cors_probed is not None:
            _, cors_headers, _, _, _ = cors_probed
            for finding in web.passive.analyze_cors(cors_headers, probe_origin=CORS_PROBE_ORIGIN):
                results.append(self._make_finding(finding, target=target, ip=ip))

        options_probed = self._fetch(base_url, method="OPTIONS")
        if options_probed is not None:
            _, opt_headers, _, _, _ = options_probed
            allow = opt_headers.get("Allow") or opt_headers.get("allow")
            for finding in web.methods.analyze_allow_header(base_url, allow):
                results.append(self._make_finding(finding, target=target, ip=ip))

        trace_marker = f"byktrace{secrets.token_hex(4)}"
        trace_probed = self._fetch(
            base_url, method="TRACE", headers={"X-Byakugan-Probe": trace_marker}
        )
        if trace_probed is not None:
            tr_status, _, tr_body, _, _ = trace_probed
            trace_finding = web.methods.analyze_trace_response(
                base_url, status_code=tr_status, body=tr_body, probe_marker=trace_marker
            )
            if trace_finding:
                results.append(self._make_finding(trace_finding, target=target, ip=ip))

        return results

    def _run_exposure(self, base_url: str, target: str, ip: str | None) -> list[RawResult]:
        from urllib.parse import urljoin

        from . import web
        from .data.web_paths import SENSITIVE_PATHS

        results: list[RawResult] = []
        random_path = f"/byakugan-{secrets.token_hex(8)}-notfound"
        baseline_probed = self._fetch(urljoin(base_url, random_path))
        baseline_status, baseline_body = (
            (baseline_probed[0], baseline_probed[2]) if baseline_probed else (404, "")
        )

        for path, signature in SENSITIVE_PATHS.items():
            probed = self._fetch(urljoin(base_url, path))
            if probed is None:
                continue
            status, _, body, _, _ = probed
            finding = web.exposure.classify_exposure(
                path=path,
                signature=signature,
                status_code=status,
                body=body,
                baseline_status=baseline_status,
                baseline_body=baseline_body,
            )
            if finding:
                results.append(self._make_finding(finding, target=target, ip=ip))

        return results

    def _run_injection(
        self,
        crawl_result: Any,
        base_url: str,
        target: str,
        ip: str | None,
        intensity: str,
    ) -> list[RawResult]:
        from . import web

        results: list[RawResult] = []
        points = self._collect_injection_points(crawl_result, base_url)[:MAX_INJECTION_POINTS]
        if not points:
            return results

        token = secrets.token_hex(4)
        checks = web.injection.build_checks(token)

        for url, param, original_value in points:
            baseline_probed = self._fetch(url)
            baseline_body = baseline_probed[2] if baseline_probed else ""

            for check in checks:
                injected_url = web.injection.build_injected_url(url, param, check.payload)
                probed = self._fetch(injected_url, allow_redirects=False)
                if probed is None:
                    continue
                status, headers, body, _, _ = probed
                response = web.injection.ProbeResponse(status, headers, body)
                evidence = check.run(response)
                if evidence:
                    finding = check.to_finding(url=url, param=param, evidence=evidence)
                    results.append(self._make_finding(finding, target=target, ip=ip))

            true_payload, false_payload = web.injection.boolean_sqli_payloads(original_value)
            true_probed = self._fetch(web.injection.build_injected_url(url, param, true_payload))
            false_probed = self._fetch(web.injection.build_injected_url(url, param, false_payload))
            if true_probed and false_probed:
                evidence = web.injection.detect_boolean_sqli(
                    true_body=true_probed[2],
                    false_body=false_probed[2],
                    baseline_body=baseline_body,
                )
                if evidence:
                    finding = {
                        "title": "Possível SQL injection (booleana)",
                        "severity": "critical",
                        "category": "injection",
                        "description": (
                            "A resposta do serviço muda de forma consistente com "
                            "condições booleanas injetadas no parâmetro, sem erro "
                            "visível — indício de SQL injection sem mensagens de erro."
                        ),
                        "evidence": f"URL: {url} | Parâmetro: '{param}' | {evidence}",
                        "recommendation": "Usar consultas parametrizadas (prepared statements).",
                    }
                    results.append(self._make_finding(finding, target=target, ip=ip))

            if intensity == "aggressive":
                for payload in (
                    *web.injection.TIME_BASED_SQLI_PAYLOADS[:1],
                    web.injection.TIME_BASED_CMDI_PAYLOAD,
                ):
                    injected_url = web.injection.build_injected_url(url, param, payload)
                    probed = self._fetch(injected_url)
                    if probed is None:
                        continue
                    elapsed = probed[4]
                    baseline_elapsed = baseline_probed[4] if baseline_probed else 0.0
                    if web.injection.detect_time_based(
                        elapsed_seconds=elapsed, baseline_elapsed_seconds=baseline_elapsed
                    ):
                        finding = {
                            "title": "Possível SQL/Command injection baseada em tempo",
                            "severity": "critical",
                            "category": "injection",
                            "description": (
                                f"A resposta demorou {elapsed:.1f}s (baseline "
                                f"{baseline_elapsed:.1f}s) após injetar um payload de "
                                "atraso deliberado — indício de execução do payload "
                                "pelo backend (SQL SLEEP()/comando shell sleep)."
                            ),
                            "evidence": f"URL: {url} | Parâmetro: '{param}' | payload='{payload}'",
                            "recommendation": (
                                "Usar consultas parametrizadas e nunca montar comandos "
                                "de shell a partir de entrada do usuário."
                            ),
                        }
                        results.append(self._make_finding(finding, target=target, ip=ip))

        return results

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Executa o pipeline completo (crawl+passive+exposure+methods+injection) por porta web."""
        context.check_cancelled()
        ip = _resolve_ip(target)
        intensity = context.options.get("intensity", "normal")
        max_pages = int(context.options.get("max_pages", 40))
        rate_delay = float(context.options.get("rate_delay", 0.1))

        results: list[RawResult] = []
        for port, scheme in WEB_SCAN_PORTS.items():
            context.check_cancelled()
            base_url = f"{scheme}://{_url_host(target)}:{port}/"
            probed = self._fetch(base_url)
            if probed is None or probed[0] >= 500:
                continue
            is_https = scheme == "https"

            results.extend(self._run_passive_and_methods(base_url, target, ip, is_https))
            context.check_cancelled()
            results.extend(self._run_exposure(base_url, target, ip))

            context.check_cancelled()
            from .web.crawler import Crawler

            def _crawler_fetch(url: str) -> tuple[int, dict[str, Any], str] | None:
                # Reaproveita o MESMO seam de rede do adapter (self._fetch) em
                # vez de duplicar a lógica de GET — também garante que mockar
                # WebScanAdapter._fetch num teste cubra o crawl também.
                probed = self._fetch(url)
                return (probed[0], probed[1], probed[2]) if probed is not None else None

            crawler = Crawler(
                max_pages=max_pages, max_depth=3, rate_delay=rate_delay, fetch=_crawler_fetch
            )
            crawl_result = crawler.crawl(base_url)

            context.check_cancelled()
            results.extend(self._run_injection(crawl_result, base_url, target, ip, intensity))

        return results


# Registry: mapeia o tipo de scan aos adapters que o compõem.
DISCOVERY_ADAPTERS: list[ScannerAdapter] = [
    DnsAdapter(),
    PortDiscoveryAdapter(),
    UdpProbeAdapter(),
    SubdomainAdapter(),
    ZoneTransferAdapter(),
    EmailSecurityAdapter(),
]
FINGERPRINT_ADAPTERS: list[ScannerAdapter] = [HttpFingerprintAdapter(), TlsAdapter()]
VULNERABILITY_ADAPTERS: list[ScannerAdapter] = [
    CveLookupAdapter(),
    DefaultCredsAdapter(),
    WebScanAdapter(),
]

ADAPTERS_BY_SCAN_TYPE: dict[str, list[ScannerAdapter]] = {
    "discovery": DISCOVERY_ADAPTERS,
    "fingerprint": FINGERPRINT_ADAPTERS,
    "vulnerability": VULNERABILITY_ADAPTERS,
    "full": [*DISCOVERY_ADAPTERS, *FINGERPRINT_ADAPTERS, *VULNERABILITY_ADAPTERS],
}


def get_adapters_for(scan_type: str, options: dict[str, Any] | None = None) -> list[ScannerAdapter]:
    """Retorna os adapters registrados para um tipo de scan.

    Quando ``options["enabled_checks"]`` é uma lista (não ``None``), o
    resultado é filtrado para os adapters cujo ``name`` esteja nela — permite
    ao cliente desligar checks específicos de um ``scan_type`` amplo (ex.:
    ``full`` sem ``cve-lookup``). ``None``/ausente mantém o comportamento
    atual (todos os adapters do tipo).
    """
    adapters = ADAPTERS_BY_SCAN_TYPE.get(scan_type, [])
    enabled_checks = (options or {}).get("enabled_checks")
    if enabled_checks is None:
        return adapters
    enabled = set(enabled_checks)
    return [adapter for adapter in adapters if adapter.name in enabled]
