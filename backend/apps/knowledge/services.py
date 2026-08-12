"""Correlação entre categorias de finding e conteúdo da Knowledge Base (Fase 6)."""

from __future__ import annotations

from .models import KnowledgeArticle

#: Categoria de fallback quando não há artigo específico para a categoria do
#: finding — garante que a busca por conhecimento relacionado quase nunca
#: fica vazia.
DEFAULT_CATEGORY = "general"


def find_article_for_category(category: str) -> KnowledgeArticle | None:
    """Retorna o artigo mais recente da categoria, com fallback para o genérico."""
    article = KnowledgeArticle.objects.filter(category=category).order_by("-created_at").first()
    if article:
        return article
    if category == DEFAULT_CATEGORY:
        return None
    return (
        KnowledgeArticle.objects.filter(category=DEFAULT_CATEGORY).order_by("-created_at").first()
    )
