"""Detecção de referências a cloud storage (S3/GCS/Azure Blob) — OWASP A05, CWE-200.

**Estritamente passiva, sem nenhuma requisição** — diferente de todos os
outros checks de exposição deste pacote. Um bucket S3/GCS/Azure referenciado
no código-fonte do site (um link de imagem, um script, um link de download)
está num **host de terceiros** (``*.amazonaws.com``, ``storage.googleapis.com``,
``*.blob.core.windows.net``), fora do `authorization_scope` do alvo — a
RN007/RN017 (escopo fail-closed) é inegociável mesmo quando o bucket foi
claramente configurado pelo próprio alvo. Por isso o Byakugan **nunca**
envia uma requisição a esses hosts para confirmar se a listagem é pública;
só reporta a referência encontrada, recomendando verificação manual das
permissões do bucket (fora do escopo técnico automatizado desta ferramenta).
"""

from __future__ import annotations

import re
from typing import Any

#: Casa URLs de bucket nos três provedores mais comuns, nos dois formatos de
#: endereço (path-style e virtual-hosted-style) de cada um.
_CLOUD_STORAGE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # S3 virtual-hosted: https://<bucket>.s3.amazonaws.com/... ou
    # https://<bucket>.s3.<região>.amazonaws.com/...
    re.compile(
        r"https?://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b",
        re.IGNORECASE,
    ),
    # S3 path-style: https://s3.amazonaws.com/<bucket>/... ou
    # https://s3.<região>.amazonaws.com/<bucket>/...
    re.compile(
        r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\b",
        re.IGNORECASE,
    ),
    # GCS virtual-hosted e path-style.
    re.compile(
        r"https?://[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]\.storage\.googleapis\.com\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]\b",
        re.IGNORECASE,
    ),
    # Azure Blob Storage: https://<conta>.blob.core.windows.net/<container>/...
    re.compile(
        r"https?://[a-z0-9]{3,24}\.blob\.core\.windows\.net/[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\b",
        re.IGNORECASE,
    ),
)


def find_cloud_storage_urls(text: str) -> list[str]:
    """Extrai referências a buckets de cloud storage (deduplicadas, ordem preservada)."""
    seen: set[str] = set()
    found: list[str] = []
    for pattern in _CLOUD_STORAGE_PATTERNS:
        for match in pattern.finditer(text or ""):
            url = match.group(0)
            if url not in seen:
                seen.add(url)
                found.append(url)
    return found


def classify_cloud_storage_reference(url: str) -> dict[str, Any]:
    """Finding de referência a cloud storage — nunca confirma exposição (sem rede).

    Severidade ``low``/categoria ``exposure``: é um indício que merece
    verificação manual, não uma prova de bucket mal configurado (que exigiria
    requisitar um host fora do escopo do alvo — ver docstring do módulo).
    """
    return {
        "title": "Referência a cloud storage encontrada no site",
        "severity": "low",
        "category": "exposure",
        "description": (
            "O código-fonte do site referencia um bucket/container de cloud "
            "storage (S3/GCS/Azure Blob) de terceiros. O Byakugan não testa a "
            "configuração desse bucket (está fora do escopo autorizado do "
            "alvo — host de terceiros), mas buckets mal configurados (listagem "
            "pública, escrita pública) são uma causa comum de vazamento de "
            "dados e merecem verificação manual das permissões."
        ),
        "evidence": f"Referência encontrada no site: {url}",
        "recommendation": (
            "Verificar manualmente (ou incluir explicitamente no escopo do "
            "engajamento) as permissões do bucket: listagem pública (ex.: "
            "`aws s3 ls s3://<bucket> --no-sign-request`), escrita pública e "
            "políticas de acesso (IAM/bucket policy)."
        ),
        "playbook_key": "exposure.cloud-storage-reference",
    }
