"""Interface de scanner adapters (integração real progressiva).

Cada capacidade de varredura é encapsulada num adapter que implementa esta
interface comum. Isso permite adicionar novas integrações (nmap, DNS, TLS,
CVE...) sem alterar o orquestrador, e trocar/mockar adapters por configuração.

Ver docs/scanning-engine.md. IMPORTANTE: todo adapter deve respeitar a
Política de Autorização de Alvos — nenhuma varredura fora do escopo autorizado.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanContext:
    """Contexto de execução repassado aos adapters.

    Attributes:
        scan_id: Identificador do scan em execução.
        authorized_by: Quem autorizou o scan (auditoria/autorização).
        authorization_scope: Escopo autorizado; o adapter não deve varrer
            nada fora dele.
        options: Parâmetros extras específicos do adapter.
    """

    scan_id: str
    authorized_by: str
    authorization_scope: str
    options: dict[str, Any] = field(default_factory=dict)


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


def _resolve_ip(host: str) -> str | None:
    """Resolve um host/domínio para um IP (retorna None se não resolver)."""
    import socket

    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


class PortDiscoveryAdapter(ScannerAdapter):
    """Descobre serviços TCP expostos via connect scan (socket).

    Usa ``socket`` puro (TCP connect) — sem depender do binário nmap. Respeita
    timeout e concorrência limitada. Nenhuma técnica de evasão é empregada;
    trata-se de uma verificação de exposição de serviços autorizados.
    """

    name = "port-discovery"
    scan_type = "discovery"

    def __init__(self, ports: dict[int, str] | None = None) -> None:
        self.ports = ports or DEFAULT_PORTS

    def _probe(self, ip: str, port: int) -> bool:
        """Tenta um TCP connect; True se a porta aceitar conexão."""
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONNECT_TIMEOUT)
            return sock.connect_ex((ip, port)) == 0

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Varre as portas comuns de ``target`` e retorna serviços abertos."""
        from concurrent.futures import ThreadPoolExecutor

        ip = _resolve_ip(target)
        if ip is None:
            return []

        results: list[RawResult] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {port: pool.submit(self._probe, ip, port) for port in self.ports}
            for port, future in futures.items():
                try:
                    is_open = future.result()
                except OSError:
                    is_open = False
                if is_open:
                    results.append(
                        RawResult(
                            kind="service",
                            data={
                                "host": target,
                                "ip": ip,
                                "port": port,
                                "protocol": "tcp",
                                "service_name": self.ports[port],
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

        ip = _resolve_ip(target)
        results: list[RawResult] = []
        seen: set[tuple[str, str]] = set()

        for port, scheme in self.ports.items():
            fetched = self._fetch(f"{scheme}://{target}:{port}/")
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


class TlsAdapter(ScannerAdapter):
    """Coleta a versão TLS negociada e o cipher do serviço HTTPS do alvo.

    Usa apenas a biblioteca padrão (``ssl``/``socket``) — sem dependências
    externas. Reporta a versão do protocolo como tecnologia; versões obsoletas
    ficam registradas na evidência para correlação futura.
    """

    name = "tls"
    scan_type = "fingerprint"

    def __init__(self, port: int = TLS_PORT) -> None:
        self.port = port

    def _probe_tls(self, host: str) -> tuple[str, str, int] | None:
        """Negocia TLS e retorna (versão, cipher, bits). None se indisponível."""
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

    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Faz o probe TLS do alvo e retorna a versão negociada como tecnologia."""
        probed = self._probe_tls(target)
        if probed is None:
            return []
        version, cipher, bits = probed
        ip = _resolve_ip(target)
        deprecated = version in DEPRECATED_TLS
        evidence = f"cipher={cipher}, bits={bits}"
        if deprecated:
            evidence += " (protocolo obsoleto)"
        return [
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


# Registry: mapeia o tipo de scan aos adapters que o compõem.
DISCOVERY_ADAPTERS: list[ScannerAdapter] = [DnsAdapter(), PortDiscoveryAdapter()]
FINGERPRINT_ADAPTERS: list[ScannerAdapter] = [HttpFingerprintAdapter(), TlsAdapter()]

ADAPTERS_BY_SCAN_TYPE: dict[str, list[ScannerAdapter]] = {
    "discovery": DISCOVERY_ADAPTERS,
    "fingerprint": FINGERPRINT_ADAPTERS,
    "full": [*DISCOVERY_ADAPTERS, *FINGERPRINT_ADAPTERS],
}


def get_adapters_for(scan_type: str) -> list[ScannerAdapter]:
    """Retorna os adapters registrados para um tipo de scan."""
    return ADAPTERS_BY_SCAN_TYPE.get(scan_type, [])
