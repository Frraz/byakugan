"""Marcadores de desserialização insegura (OWASP A08, CWE-502).

Puramente passivo — nenhuma requisição extra: opera sobre cookies/corpo já
obtidos pelo probe base e pelo crawl do ``WebScanAdapter``. Não tenta
desserializar nem explorar nada (isso exigiria uma gadget chain específica
do framework/classpath do alvo, via ferramentas como ysoserial/ysoserial.net
— fora do escopo de uma detecção genérica e não-destrutiva); só reconhece
**assinaturas conhecidas** de que o backend usa serialização nativa de
objeto (Java/.NET/PHP) para transportar estado client-side — o precursor
clássico de RCE via gadget chain, mesmo sem confirmar o gadget em si.

Três sinais, cada um documentado por que é confiável:

- **Java**: o stream de serialização Java sempre começa com os bytes
  ``AC ED 00 05`` — em Base64 isso é sempre o prefixo ``rO0AB`` (determinístico,
  não há falso positivo por coincidência em texto normal). O cookie
  ``rememberMe`` do Apache Shiro é a instância mais famosa e mais explorada
  na prática (Shiro-550, CVE-2016-4437) — ganha um finding dedicado de maior
  confiança além da assinatura genérica.
- **PHP**: o formato ``serialize()`` nativo do PHP para objetos é
  ``O:<tamanho>:"<classe>":<n_props>:{...}`` — uma assinatura estrutural
  praticamente impossível de ocorrer por acaso em texto livre.
- **.NET ViewState**: a presença do campo ``__VIEWSTATE`` identifica Web
  Forms ASP.NET clássico, que historicamente permite RCE via
  ysoserial.net quando ``EnableViewStateMac``/criptografia estão desligados
  — um sinal que o cliente não consegue confirmar sozinho, então o finding é
  **informativo** (severidade baixa), recomendando verificação manual.
"""

from __future__ import annotations

import re
from typing import Any

#: Base64 de ``AC ED 00 05`` (header de todo stream de serialização Java) —
#: prefixo determinístico, nunca varia. Exige alguns caracteres adicionais
#: para reduzir ainda mais a (já baixíssima) chance de correspondência
#: coincidental em texto livre.
_JAVA_MAGIC_RE = re.compile(r"\brO0[A-Za-z0-9+/]{8,}={0,2}")

#: Assinatura estrutural do PHP ``serialize()`` para objetos.
_PHP_OBJECT_RE = re.compile(r'O:\d+:"[A-Za-z_][A-Za-z0-9_\\]*":\d+:\{')


def _finding(
    *,
    title: str,
    severity: str,
    description: str,
    evidence: str,
    recommendation: str,
    playbook_key: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "category": "integrity",
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "playbook_key": playbook_key,
    }


def detect_java_serialized_cookie(cookies: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Detecta um cookie com objeto Java serializado (ou o 'rememberMe' do Shiro)."""
    for cookie in cookies:
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        if name.lower() == "remember-me" or name.lower() == "rememberme":
            return _finding(
                title="Cookie 'rememberMe' do Apache Shiro detectado",
                severity="critical",
                description=(
                    "O cookie 'rememberMe', característico do Apache Shiro, foi "
                    "encontrado — versões do Shiro com a chave de criptografia "
                    "padrão/fraca (AES-128-CBC) permitem forjar um objeto Java "
                    "serializado malicioso nesse cookie e obter execução remota "
                    "de código ao ser desserializado pelo servidor (Shiro-550, "
                    "CVE-2016-4437), usando uma gadget chain conhecida "
                    "(ysoserial)."
                ),
                evidence=f"Cookie '{name}' presente na resposta.",
                recommendation=(
                    "Atualizar o Apache Shiro para uma versão corrigida e "
                    "trocar a chave de criptografia do 'rememberMe' por um "
                    "valor aleatório exclusivo (nunca a chave padrão de exemplo)."
                ),
                playbook_key="integrity.java-deserialization",
            )
        match = _JAVA_MAGIC_RE.search(value)
        if match:
            return _finding(
                title="Cookie com objeto Java serializado",
                severity="high",
                description=(
                    f"O cookie '{name}' contém um valor cujo prefixo Base64 "
                    "decodifica para a assinatura de um stream de serialização "
                    "Java (AC ED 00 05) — o backend provavelmente desserializa "
                    "esse cookie, um vetor clássico de RCE via gadget chain "
                    "(ex.: Commons Collections, Spring) se a biblioteca "
                    "estiver no classpath."
                ),
                evidence=f"Cookie '{name}' | valor começa com '{match.group(0)[:20]}...'.",
                recommendation=(
                    "Nunca desserializar dados controlados pelo cliente com "
                    "Java nativo; usar um formato seguro (JSON) ou, se "
                    "inevitável, uma allowlist de classes deserializáveis "
                    "(ex.: ObjectInputFilter do JEP 290)."
                ),
                playbook_key="integrity.java-deserialization",
            )
    return None


def detect_java_serialized_in_body(*, url: str, body: str) -> dict[str, Any] | None:
    """Detecta um objeto Java serializado embutido no corpo de uma página."""
    match = _JAVA_MAGIC_RE.search(body or "")
    if not match:
        return None
    return _finding(
        title="Objeto Java serializado exposto na página",
        severity="high",
        description=(
            "Um valor Base64 no corpo da página decodifica para a assinatura "
            "de um stream de serialização Java (AC ED 00 05) — indício de "
            "estado da aplicação transportado via objeto Java serializado "
            "(campo oculto, token, parâmetro embutido), um vetor clássico de "
            "RCE via gadget chain se esse valor for aceito de volta pelo servidor."
        ),
        evidence=f"URL: {url} | Parâmetro: '' | Corpo contém '{match.group(0)[:20]}...'.",
        recommendation=(
            "Nunca desserializar dados controlados pelo cliente com Java "
            "nativo; usar um formato seguro (JSON) ou uma allowlist de "
            "classes deserializáveis."
        ),
        playbook_key="integrity.java-deserialization",
    )


def detect_php_serialized_in_body(*, url: str, body: str) -> dict[str, Any] | None:
    """Detecta um objeto PHP serializado no corpo de uma página."""
    match = _PHP_OBJECT_RE.search(body or "")
    if not match:
        return None
    return _finding(
        title="Objeto PHP serializado exposto na página",
        severity="high",
        description=(
            "O corpo da página contém a assinatura estrutural do "
            'serialize() nativo do PHP para objetos (O:<n>:"Classe":...) '
            "— se esse valor voltar ao servidor (cookie/parâmetro) e for "
            "passado a unserialize() sem validação, um objeto malicioso "
            "pode acionar métodos mágicos (__wakeup/__destruct) de classes "
            "do próprio código ou de bibliotecas (PHP Object Injection → "
            "RCE/escrita de arquivo, dependendo da gadget chain disponível)."
        ),
        evidence=f"URL: {url} | Parâmetro: '' | Corpo contém '{match.group(0)[:60]}'.",
        recommendation=(
            "Nunca usar unserialize() sobre dados controlados pelo cliente; "
            "usar json_decode() ou, se inevitável, "
            "unserialize($data, ['allowed_classes' => false])."
        ),
        playbook_key="integrity.php-object-injection",
    )


def detect_php_serialized_cookie(cookies: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Detecta um cookie com objeto PHP serializado."""
    for cookie in cookies:
        value = str(cookie.get("value") or "")
        match = _PHP_OBJECT_RE.search(value)
        if match:
            name = cookie.get("name", "?")
            return _finding(
                title="Cookie com objeto PHP serializado",
                severity="high",
                description=(
                    f"O cookie '{name}' contém a assinatura estrutural do "
                    "serialize() nativo do PHP para objetos — se esse valor "
                    "for passado a unserialize() no servidor, um objeto "
                    "malicioso pode acionar métodos mágicos de classes "
                    "disponíveis (PHP Object Injection)."
                ),
                evidence=f"Cookie '{name}' | valor contém '{match.group(0)[:60]}'.",
                recommendation=(
                    "Nunca usar unserialize() sobre dados controlados pelo "
                    "cliente; usar json_decode() ou "
                    "unserialize($data, ['allowed_classes' => false])."
                ),
                playbook_key="integrity.php-object-injection",
            )
    return None


def detect_viewstate(*, url: str, form: dict[str, Any]) -> dict[str, Any] | None:
    """Sinaliza (informativo) a presença de ASP.NET ViewState sem criptografia explícita.

    Não é possível confirmar ``EnableViewStateMac``/criptografia só pelo
    HTML — por isso o finding é severidade ``low``/informativo, nunca uma
    afirmação de vulnerabilidade confirmada.
    """
    inputs = [str(name) for name in form.get("inputs", [])]
    lowered = [name.lower() for name in inputs]
    if "__viewstate" not in lowered:
        return None
    if "__viewstateencrypted" in lowered:
        return None  # app já sinaliza que o ViewState é criptografado
    return _finding(
        title="ASP.NET ViewState sem indicação de criptografia",
        severity="low",
        description=(
            "O formulário usa ASP.NET Web Forms clássico (campo "
            "__VIEWSTATE) sem o campo __VIEWSTATEENCRYPTED, que indicaria "
            "criptografia explícita. Se EnableViewStateMac/criptografia "
            "estiverem desabilitados no servidor (não confirmável só pelo "
            "HTML), o ViewState pode ser adulterado e desserializado "
            "maliciosamente (RCE via ysoserial.net) — requer verificação manual."
        ),
        evidence=f"URL: {url} | Parâmetro: '' | Formulário com campo __VIEWSTATE, sem __VIEWSTATEENCRYPTED.",
        recommendation=(
            "Confirmar que EnableViewStateMac está ativo (padrão desde "
            ".NET 4.5.2) e considerar criptografar o ViewState "
            "(ViewStateEncryptionMode=Always) ou migrar para ASP.NET MVC/"
            "Core (sem ViewState)."
        ),
        playbook_key="integrity.viewstate-exposed",
    )
