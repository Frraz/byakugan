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


def _detect_xss(response: ProbeResponse, payload: str, baseline_body: str) -> str | None:
    # Marcador único por scan (``bykxss<token>``) — zero risco de já estar no
    # baseline por coincidência, baseline não é necessário aqui.
    if payload in response.body:
        return f"Marcador injetado refletido sem escape HTML: '{payload}' presente na resposta."
    return None


def _detect_sqli_error(response: ProbeResponse, payload: str, baseline_body: str) -> str | None:
    for pattern in _SQL_ERROR_PATTERNS:
        match = pattern.search(response.body)
        if match and match.group(0) not in baseline_body:
            return f"Assinatura de erro de banco de dados na resposta: '{match.group(0)[:80]}'."
    return None


def _detect_traversal(response: ProbeResponse, payload: str, baseline_body: str) -> str | None:
    # Assinatura de /etc/passwd — estruturalmente improvável no baseline de
    # uma aplicação web normal; não precisa de comparação.
    if _TRAVERSAL_RE.search(response.body):
        return "Conteúdo de /etc/passwd (padrão 'root:...:0:0:') encontrado na resposta."
    return None


def _detect_redirect(response: ProbeResponse, payload: str, baseline_body: str) -> str | None:
    # Marcador de domínio reservado único — não precisa de baseline (o
    # header Location do baseline nunca aponta pra ele por definição).
    if response.status_code not in _REDIRECT_STATUS_CODES:
        return None
    location = response.headers.get("Location") or response.headers.get("location") or ""
    if REDIRECT_MARKER in location:
        return f"Header Location aponta para o domínio de teste injetado: '{location}'."
    return None


def _detect_ssti(response: ProbeResponse, payload: str, baseline_body: str) -> str | None:
    # '49' é um número mundano que pode aparecer no conteúdo normal da
    # página (ex.: "Mostrando 49 resultados") sem relação com a injeção —
    # só confirma se o próprio baseline (sem payload) NÃO tiver o mesmo match.
    match = _SSTI_RE.search(response.body)
    if match and not _SSTI_RE.search(baseline_body):
        return f"Expressão de template '{payload}' avaliada — '49' encontrado na resposta (ausente do baseline)."
    return None


def _detect_cmdi(response: ProbeResponse, payload: str, baseline_body: str) -> str | None:
    match = _CMDI_RE.search(response.body)
    if match and match.group(0) not in baseline_body:
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


def _detect_ssrf(response: ProbeResponse, payload: str, baseline_body: str) -> str | None:
    # 'meta-data/' isolado é genérico o bastante para aparecer por acaso num
    # path/URL não relacionado — exige ausência do mesmo match no baseline.
    match = _SSRF_RE.search(response.body)
    if match and match.group(0) not in baseline_body:
        return "Metadata de nuvem/interno refletido na resposta — o servidor buscou a URL injetada (SSRF)."
    return None


# --- CRLF Injection / HTTP Response Splitting --------------------------------
# Injeta uma sequência CRLF (``\r\n``) seguida de um header sintético no
# parâmetro. Se o backend concatena o valor recebido direto num header de
# resposta (ex.: Location de um redirect, Set-Cookie) sem sanitizar CR/LF, o
# cliente HTTP recebe um header EXTRA genuíno (``X-Byakugan-Crlf: injected``)
# — o parsing HTTP padrão (``requests``/``urllib3``) já o separa corretamente
# em ``response.headers``, então basta checar sua presença.
CRLF_HEADER_NAME = "x-byakugan-crlf"
CRLF_HEADER_VALUE = "injected"
CRLF_PAYLOAD = f"byk\r\n{CRLF_HEADER_NAME}: {CRLF_HEADER_VALUE}"


def _detect_crlf_injection(response: ProbeResponse, payload: str, baseline_body: str) -> str | None:
    # Header sintético com nome/valor fixos do scanner — não precisa de
    # baseline (um alvo real jamais teria esse header por coincidência).
    for key, value in response.headers.items():
        if key.lower() == CRLF_HEADER_NAME and value.strip().lower() == CRLF_HEADER_VALUE:
            return (
                f"Header '{key}: {value}' injetado via CRLF apareceu como header de resposta "
                "genuíno e separado — o valor do parâmetro foi concatenado sem sanitização "
                "num header de resposta."
            )
    return None


# --- Host Header Injection ---------------------------------------------------
# Domínio reservado (RFC 2606, nunca resolve de verdade) enviado no header
# Host em vez da URL — se o servidor confiar nesse header para montar links
# absolutos (reset de senha, canonical, redirects), ele "volta" na resposta.
HOST_HEADER_MARKER = "byakugan-hhi-probe.invalid"


def detect_host_header_reflection(
    *, status_code: int, headers: dict[str, str], body: str, marker: str = HOST_HEADER_MARKER
) -> str | None:
    """Detecta reflexão do header ``Host`` injetado na resposta.

    Dois sinais, sem distinguir qual — ambos provam a mesma falha (o backend
    confia no header ``Host`` controlado pelo cliente em vez da configuração
    do servidor): o marcador aparece no header ``Location`` de um redirect,
    ou aparece no corpo (ex.: um link absoluto de reset de senha/canonical
    montado a partir do Host recebido).
    """
    location = headers.get("Location") or headers.get("location") or ""
    if marker in location:
        return f"Header Location reflete o Host injetado: '{location}'."
    if marker in body:
        return f"Corpo da resposta reflete o Host injetado ('{marker}') — provável link absoluto montado a partir do header Host."
    return None


# --- NoSQL injection (booleana) ---------------------------------------------
# Operadores MongoDB (``$ne``/``$eq``) expressos como chave de query string —
# frameworks que fazem parsing "rico" de query strings (ex.: Express + qs)
# interpretam ``param[$ne]=x`` como ``{param: {"$ne": "x"}}`` se o valor for
# passado direto para uma consulta Mongo sem validação de tipo/schema.


def build_nosqli_injected_url(url: str, param: str, operator: str, value: str) -> str:
    """Substitui a chave ``param`` por ``param[operator]`` na query string.

    Diferente de ``build_injected_url`` (que só troca o *valor*), aqui a
    *chave* muda — é assim que um parser tipo ``qs``/PHP interpreta um
    operador de consulta vindo da URL.
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    query_pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    query_pairs.append((f"{param}[{operator}]", value))
    new_query = urlencode(query_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _similar_response(a: str, b: str, *, abs_min: int = 15, rel: float = 0.03) -> bool:
    """True se dois corpos têm tamanho parecido — comparador compartilhado
    pelas duas heurísticas booleanas (SQLi e NoSQLi) desta classe."""
    if not a and not b:
        return True
    longer = max(len(a), len(b), 1)
    return abs(len(a) - len(b)) <= max(abs_min, int(longer * rel))


def detect_boolean_nosqli(*, bypass_body: str, exact_body: str, baseline_body: str) -> str | None:
    """Compara respostas a um operador de bypass (``$ne``) × busca exata inexistente.

    ``bypass_body``: resposta a ``param[$ne]=<valor-aleatório>`` — se o
    parser interpretar o operador, isso equivale a "diferente de um valor
    que nunca existiria", ou seja, continua casando o registro original
    (resposta ≈ baseline). ``exact_body``: resposta a ``param[$eq]=<mesmo
    valor aleatório>`` — uma busca exata por algo inexistente deveria não
    casar nada (resposta ≠ baseline). O padrão condicional (bypass ≈
    baseline, exact ≠ baseline) só aparece se a chave ``[$ne]``/``[$eq]``
    foi de fato interpretada como operador pelo backend.
    """
    if _similar_response(bypass_body, baseline_body) and not _similar_response(
        exact_body, baseline_body
    ):
        return (
            "Resposta ao operador de bypass ('param[$ne]=<valor aleatório>') é "
            "semelhante ao baseline, mas a busca exata pelo mesmo valor "
            "inexistente ('param[$eq]=<mesmo valor>') resulta em resposta "
            "significativamente diferente — indício de que a chave de query foi "
            "interpretada como operador de consulta (NoSQL injection)."
        )
    return None


# --- LDAP injection (booleana) -----------------------------------------------
# Mesma estratégia das booleanas acima, adaptada à sintaxe de filtro LDAP:
# um wildcard ('*') amplia o match sem quebrar a sintaxe de um filtro
# concatenado (ex.: "(uid=<valor>)"), então o "verdadeiro" tende a continuar
# parecido com o baseline; um fechamento de filtro seguido de um atributo
# inexistente só muda a resposta se o valor for de fato interpretado como
# parte da estrutura do filtro — se não for (não vulnerável), vira apenas
# uma busca literal por uma string que não existe, igualmente sem match.


def ldap_boolean_payloads(original_value: str) -> tuple[str, str]:
    """``(payload_verdadeiro, payload_falso)`` — anexados ao valor original do parâmetro."""
    return f"{original_value}*", f"{original_value})(uid=byaknoexist"


def detect_boolean_ldap(*, true_body: str, false_body: str, baseline_body: str) -> str | None:
    """Compara respostas a um wildcard LDAP × um fechamento de filtro injetado.

    Comportamento condicional (wildcard ≈ baseline, fechamento de filtro ≠
    baseline) indica que o valor é concatenado sem escape num filtro LDAP
    (``(uid=<valor>)``) — a assinatura booleana clássica, sem depender de
    mensagem de erro visível.
    """
    if _similar_response(true_body, baseline_body) and not _similar_response(
        false_body, baseline_body
    ):
        return (
            'Resposta ao wildcard LDAP ("valor*") é semelhante ao baseline, mas '
            'fechar o filtro e injetar um atributo inexistente ("valor)(uid='
            'byaknoexist") resulta em resposta significativamente diferente — '
            "comportamento condicional típico de LDAP injection."
        )
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
    detect: Callable[[ProbeResponse, str, str], str | None]
    #: Classe de vulnerabilidade (``Finding.playbook_key``) — liga o finding ao
    #: playbook curado (aba Evidências) e ao módulo de exploração. Vários checks
    #: podem mapear para o mesmo playbook (ex.: ssti-dollar/ssti-mustache →
    #: ``injection.ssti``).
    playbook_key: str = ""

    def run(self, response: ProbeResponse, baseline_body: str = "") -> str | None:
        """``baseline_body`` (opcional): corpo da MESMA URL sem o payload injetado.

        Disciplina de red team sênior — nunca confiar num sinal sem checar se
        ele já estava lá antes da injeção: detectores cujo sinal é um valor
        mundano que pode aparecer por acaso no conteúdo normal da página
        (ex.: SSTI procurando o número '49') só reportam se o sinal estiver
        ausente do baseline. Detectores com marcador único por scan (XSS) ou
        assinatura estruturalmente improvável de ocorrer por acaso (traversal,
        redirect, CRLF) ignoram o parâmetro — não precisam dele.
        """
        return self.detect(response, self.payload, baseline_body)

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
        InjectionCheck(
            key="crlf",
            title="Possível CRLF Injection / HTTP Response Splitting",
            severity="high",
            payload=CRLF_PAYLOAD,
            description=(
                "A injeção de uma sequência CRLF ('\\r\\n') seguida de um header "
                "sintético no parâmetro resultou num header de resposta HTTP extra "
                "e genuíno — o valor é concatenado sem sanitização num header de "
                "resposta (ex.: Location, Set-Cookie), permitindo injetar headers "
                "arbitrários ou, em alguns servidores, dividir a resposta em duas "
                "(response splitting)."
            ),
            recommendation=(
                "Nunca concatenar entrada do usuário diretamente em headers de "
                "resposta; remover/rejeitar CR/LF da entrada e usar as APIs do "
                "framework para setar headers (que normalmente já sanitizam)."
            ),
            detect=_detect_crlf_injection,
            playbook_key="injection.crlf",
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

    if _similar_response(true_body, baseline_body) and not _similar_response(
        false_body, baseline_body
    ):
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
