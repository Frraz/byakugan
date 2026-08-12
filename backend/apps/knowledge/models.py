"""Modelo de conteúdo da Knowledge Base (RF014, RN013)."""

from django.db import models

from apps.core.models import BaseModel


class KnowledgeArticle(BaseModel):
    """Conteúdo explicativo e de remediação por categoria de vulnerabilidade.

    Diferente de ``Vulnerability``/``Finding``/``Report`` (histórico imutável
    — RN003), artigos da Knowledge Base são conteúdo de referência **vivo**:
    podem ser editados/atualizados conforme o entendimento evolui.

    ``category`` casa com a mesma taxonomia livre usada em ``Finding.category``
    (ex.: ``software``, ``tls``, ``web``, ``network``, ``cms``) — múltiplos
    artigos podem existir por categoria; a categoria ``general`` funciona como
    fallback quando não há artigo específico (ver ``services.py``).
    """

    slug = models.SlugField(max_length=100, unique=True)
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=50, db_index=True)
    summary = models.TextField()
    impact = models.TextField()
    remediation_steps = models.JSONField(default=list)
    references = models.JSONField(default=list, blank=True)

    def __str__(self) -> str:
        return self.title
