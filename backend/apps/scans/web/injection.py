"""Detecção de injeção em parâmetros web (Fase 4 — detecção, nunca exploração).

Cada verificação injeta um valor único/inofensivo num parâmetro e procura um
sinal inequívoco de que o valor voltou interpretado pelo backend (reflexão
sem escape, erro de banco, execução de comando) — nunca um payload que
danifique dados ou explore de fato a vulnerabilidade. Ex.: o probe de XSS
usa a tag inerte ``<b>`` em vez de ``<script>`` — se o alvo tiver XSS
**armazenado** (não refletido), um payload ``<script>`` salvo poderia
executar depois contra usuários reais; ``<b>`` prova a mesma ausência de
escaping sem esse risco. Funções puras: recebem a resposta já obtida pelo
adapter, nunca fazem I/O.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# --- Path traversal / LFI ----------------------------------------------------

TRAVERSAL_PAYLOAD = "../../../../../../../../etc/passwd"
_TRAVERSAL_RE = re.compile(r"root:.*?:0:0:")

# --- Open redirect ------------------------------------------------------
# Domínio reservado pela IANA (RFC 2606) para nunca resolver de verdade —
# mesmo que algo siga o redirect automaticamente, não alcança infraestrutura real.
REDIRECT_MARKER = "byakugan-redirect-probe.invalid"
REDIRECT_PAYLOAD = f"//{REDIRECT_MARKER}/"
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

# --- SSTI -----------------------------------------------------------------

SSTI_PAYLOAD_DOLLAR = "${7*7}"
SSTI_PAYLOAD_MUSTACHE = "{{7*7}}"
_SSTI_RE = re.compile(r"\b49\b")

# --- Command injection ----------------------------------------------------

COMMAND_INJECTION_PAYLOAD = ";id"
_CMDI_RE = re.compile(r"uid=\d+\([^)]*\)\s*gid=\d+\(")

# --- SQL injection (erro) --------------------------------------------------

SQLI_ERROR_PAYLOAD = "'"
_SQL_ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*?MySQL", re.IGNORECASE),
    re.compile(r"Warning.*?\Wmysqli?_", re.IGNORECASE),
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"PostgreSQL.*?ERROR", re.IGNORECASE),
    re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"SQLite3?::(SQLException|query)", re.IGNORECASE),
    re.compile(r"System\.Data\.SQLite\.SQLiteException", re.IGNORECASE),
    re.compile(r"Warning.*?\Wpg_", re.IGNORECASE),
    re.compile(r"SQLSTATE\[\d+\]", re.IGNORECASE),
]


def build_injected_url(url: str, param: str, value: str) -> str:
    """Substitui o valor de ``param`` em ``url`` por ``value``, preservando os demais.

    Usa ``parse_qsl``/``urlencode`` em vez de deixar o ``requests`` mesclar
    um dict ``params=`` na URL — mesclar poderia DUPLICAR a chave (ex.:
    ``?id=5`` + ``params={"id": "x"}`` → ``?id=5&id=x``) em vez de
    substituir, deixando o ponto de injeção "sujo".
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    new_pairs = [(k, value if k == param else v) for k, v in query_pairs]
    if param not in {k for k, _ in query_pairs}:
        new_pairs.append((param, value))
    new_query = urlencode(new_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


@dataclass(frozen=True)
class ProbeResponse:
    """Resposta HTTP normalizada, já obtida pelo adapter — sem I/O aqui."""

    status_code: int
    headers: dict[str, str]
    body: str


def _detect_xss(response: ProbeResponse, payload: str) -> str | None:
    if payload in response.body:
        return f"Marcador injetado refletido sem escape HTML: '{payload}' presente na resposta."
    return None


def _detect_sqli_error(response: ProbeResponse, payload: str) -> str | None:
    for pattern in _SQL_ERROR_PATTERNS:
        match = pattern.search(response.body)
        if match:
            return f"Assinatura de erro de banco de dados na resposta: '{match.group(0)[:80]}'."
    return None


def _detect_traversal(response: ProbeResponse, payload: str) -> str | None:
    if _TRAVERSAL_RE.search(response.body):
        return "Conteúdo de /etc/passwd (padrão 'root:...:0:0:') encontrado na resposta."
    return None


def _detect_redirect(response: ProbeResponse, payload: str) -> str | None:
    if response.status_code not in _REDIRECT_STATUS_CODES:
        return None
    location = response.headers.get("Location") or response.headers.get("location") or ""
    if REDIRECT_MARKER in location:
        return f"Header Location aponta para o domínio de teste injetado: '{location}'."
    return None


def _detect_ssti(response: ProbeResponse, payload: str) -> str | None:
    if _SSTI_RE.search(response.body):
        return f"Expressão de template '{payload}' avaliada — '49' encontrado na resposta."
    return None


def _detect_cmdi(response: ProbeResponse, payload: str) -> str | None:
    if _CMDI_RE.search(response.body):
        return "Saída de comando do sistema (padrão 'uid=...gid=...') encontrada na resposta."
    return None


# --- SSRF --------------------------------------------------------------------
# Aponta o parâmetro para o endpoint de metadata da nuvem (read-only). Se a
# resposta trouxer marcadores de metadata, o servidor buscou a URL controlada
# pelo usuário — SSRF confirmado, sem tocar em nada do alvo.
SSRF_PAYLOAD = "http://169.254.169.254/latest/meta-data/"
_SSRF_RE = re.compile(
    r"(ami-id|instance-id|iam/security-credentials|computeMetadata|placement/|meta-data/)",
    re.IGNORECASE,
)


def _detect_ssrf(response: ProbeResponse, payload: str) -> str | None:
    if _SSRF_RE.search(response.body):
        return "Metadata de nuvem/interno refletido na resposta — o servidor buscou a URL injetada (SSRF)."
    return None


@dataclass(frozen=True)
class InjectionCheck:
    """Uma verificação de injeção de requisição única: payload → detector."""

    key: str
    title: str
    severity: str
    payload: str
    description: str
    recommendation: str
    detect: Callable[[ProbeResponse, str], str | None]
    #: Classe de vulnerabilidade (``Finding.playbook_key``) — liga o finding ao
    #: playbook curado (aba Evidências) e ao módulo de exploração. Vários checks
    #: podem mapear para o mesmo playbook (ex.: ssti-dollar/ssti-mustache →
    #: ``injection.ssti``).
    playbook_key: str = ""

    def run(self, response: ProbeResponse) -> str | None:
        return self.detect(response, self.payload)

    def to_finding(self, *, url: str, param: str, evidence: str) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "category": "injection",
            "description": self.description,
            "evidence": f"URL: {url} | Parâmetro: '{param}' | {evidence}",
            "recommendation": self.recommendation,
            "playbook_key": self.playbook_key,
        }


def build_checks(token: str) -> list[InjectionCheck]:
    """Monta os checks de requisição única — ``token`` torna o marcador de XSS único por scan."""
    return [
        InjectionCheck(
            key="xss",
            title="Possível XSS refletido",
            severity="high",
            payload=f"bykxss{token}<b>bykxssend{token}",
            description=(
                "O valor injetado (incluindo uma tag HTML) foi refletido na resposta "
                "sem codificação — um atacante poderia injetar HTML/script arbitrário "
                "neste parâmetro."
            ),
            recommendation="Codificar (HTML-encode) toda entrada do usuário antes de refleti-la no HTML.",
            detect=_detect_xss,
            playbook_key="injection.xss",
        ),
        InjectionCheck(
            key="sqli-error",
            title="Possível SQL injection (baseada em erro)",
            severity="critical",
            payload=SQLI_ERROR_PAYLOAD,
            description=(
                "A injeção de uma aspa simples no parâmetro produziu uma mensagem de "
                "erro de banco de dados na resposta — indício de que o valor é "
                "concatenado diretamente numa consulta SQL sem parametrização."
            ),
            recommendation="Usar consultas parametrizadas (prepared statements) em vez de concatenar entrada do usuário.",
            detect=_detect_sqli_error,
            playbook_key="injection.sqli-error",
        ),
        InjectionCheck(
            key="path-traversal",
            title="Possível path traversal / Local File Inclusion",
            severity="critical",
            payload=TRAVERSAL_PAYLOAD,
            description=(
                "A injeção de uma sequência de travessia de diretório ('../') resultou "
                "no conteúdo de um arquivo sensível do sistema (/etc/passwd) na resposta."
            ),
            recommendation=(
                "Validar/normalizar caminhos de arquivo contra uma allowlist e nunca "
                "montar caminhos a partir de entrada do usuário sem sanitização."
            ),
            detect=_detect_traversal,
            playbook_key="injection.path-traversal",
        ),
        InjectionCheck(
            key="open-redirect",
            title="Possível open redirect",
            severity="medium",
            payload=REDIRECT_PAYLOAD,
            description=(
                "A injeção de uma URL externa no parâmetro fez o serviço redirecionar "
                "(HTTP 3xx) para o domínio de teste injetado — um atacante poderia "
                "usar isso para phishing (URL do domínio confiável redirecionando para "
                "um site malicioso)."
            ),
            recommendation="Validar destinos de redirecionamento contra uma allowlist de URLs/domínios internos.",
            detect=_detect_redirect,
            playbook_key="injection.open-redirect",
        ),
        InjectionCheck(
            key="ssti-dollar",
            title="Possível Server-Side Template Injection (SSTI)",
            severity="critical",
            payload=SSTI_PAYLOAD_DOLLAR,
            description=(
                "A expressão de template injetada (sintaxe '${...}', comum em "
                "FreeMarker/Java EL) foi avaliada pelo servidor — o resultado da "
                "operação matemática apareceu na resposta em vez da expressão literal."
            ),
            recommendation="Nunca renderizar entrada do usuário como template; usar apenas como dado/variável.",
            detect=_detect_ssti,
            playbook_key="injection.ssti",
        ),
        InjectionCheck(
            key="ssti-mustache",
            title="Possível Server-Side Template Injection (SSTI)",
            severity="critical",
            payload=SSTI_PAYLOAD_MUSTACHE,
            description=(
                "A expressão de template injetada (sintaxe '{{...}}', comum em "
                "Jinja2/Twig/Handlebars) foi avaliada pelo servidor — o resultado da "
                "operação matemática apareceu na resposta em vez da expressão literal."
            ),
            recommendation="Nunca renderizar entrada do usuário como template; usar apenas como dado/variável.",
            detect=_detect_ssti,
            playbook_key="injection.ssti",
        ),
        InjectionCheck(
            key="command-injection",
            title="Possível Command Injection",
            severity="critical",
            payload=COMMAND_INJECTION_PAYLOAD,
            description=(
                "A injeção de um separador de comando shell (';') seguido de 'id' "
                "produziu saída típica desse comando do sistema (uid=.../gid=...) na "
                "resposta — indício de que o valor é passado para um shell sem sanitização."
            ),
            recommendation="Nunca montar comandos de shell a partir de entrada do usuário; usar APIs específicas sem shell.",
            detect=_detect_cmdi,
            playbook_key="injection.command-injection",
        ),
        InjectionCheck(
            key="ssrf",
            title="Possível Server-Side Request Forgery (SSRF)",
            severity="high",
            payload=SSRF_PAYLOAD,
            description=(
                "Ao injetar uma URL de recurso interno (endpoint de metadata da nuvem) "
                "no parâmetro, a resposta trouxe conteúdo interno — o servidor buscou a "
                "URL controlada pelo usuário, permitindo alcançar serviços internos "
                "inacessíveis de fora."
            ),
            recommendation=(
                "Validar destinos de requisição do servidor contra uma allowlist; "
                "bloquear IPs internos/link-local (169.254.0.0/16, 127.0.0.0/8) e "
                "seguir redirects com cuidado."
            ),
            detect=_detect_ssrf,
            playbook_key="injection.ssrf",
        ),
    ]


# --- SQLi booleana (duas requisições: verdadeira × falsa vs. baseline) ------


def boolean_sqli_payloads(original_value: str) -> tuple[str, str]:
    """``(payload_verdadeiro, payload_falso)`` — anexados ao valor original do parâmetro."""
    return f"{original_value}' AND '1'='1", f"{original_value}' AND '1'='2"


def detect_boolean_sqli(*, true_body: str, false_body: str, baseline_body: str) -> str | None:
    """Compara respostas a condições sempre-verdadeira/falsa injetadas contra o baseline.

    Comportamento condicional (verdadeira ≈ baseline, falsa ≠ baseline) é a
    assinatura clássica de SQL injection booleana — sem depender de erro
    visível na resposta.
    """

    def _similar(a: str, b: str) -> bool:
        if not a and not b:
            return True
        longer = max(len(a), len(b), 1)
        return abs(len(a) - len(b)) <= max(15, int(longer * 0.03))

    if _similar(true_body, baseline_body) and not _similar(false_body, baseline_body):
        return (
            "Resposta com condição sempre-verdadeira (\"1'='1\") é semelhante ao "
            "baseline, mas a condição sempre-falsa (\"1'='2\") resulta em resposta "
            "significativamente diferente — comportamento condicional típico de SQL "
            "injection booleana."
        )
    return None


# --- Time-based (SQLi/command injection) — gated em intensity="aggressive" ---

TIME_BASED_SQLI_PAYLOADS: tuple[str, ...] = (
    "' AND SLEEP(5)-- -",
    "1 AND SLEEP(5)-- -",
    "'; SELECT PG_SLEEP(5)-- -",
)
TIME_BASED_CMDI_PAYLOAD = "; sleep 5"
TIME_BASED_THRESHOLD_SECONDS = 4.0


def detect_time_based(*, elapsed_seconds: float, baseline_elapsed_seconds: float) -> bool:
    """True se o probe demorou consideravelmente mais que o baseline (SLEEP/sleep executado)."""
    return (elapsed_seconds - baseline_elapsed_seconds) >= TIME_BASED_THRESHOLD_SECONDS
