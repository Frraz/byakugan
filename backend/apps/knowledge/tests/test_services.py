"""Testes da correlação categoria → artigo da Knowledge Base (Fase 6)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.knowledge.models import KnowledgeArticle
from apps.knowledge.services import find_article_for_category

pytestmark = pytest.mark.django_db


def _make_article(**overrides):
    defaults = {
        "title": "Artigo de teste",
        "category": "custom",
        "summary": "resumo",
        "impact": "impacto",
        "remediation_steps": ["passo 1"],
    }
    defaults.update(overrides)
    return KnowledgeArticle.objects.create(**defaults)


def test_finds_seeded_software_article():
    """A migração de dados semeia um artigo real para a categoria software."""
    article = find_article_for_category("software")
    assert article is not None
    assert article.slug == "outdated-software"


def test_finds_most_recent_article_for_category():
    older = _make_article(slug="custom-1", category="custom")
    KnowledgeArticle.objects.filter(id=older.id).update(
        created_at=timezone.now() - timedelta(days=1)
    )
    newest = _make_article(slug="custom-2", category="custom")

    article = find_article_for_category("custom")

    assert article.id == newest.id


def test_falls_back_to_general_category():
    article = find_article_for_category("nonexistent-category-xyz")
    assert article is not None
    assert article.category == "general"


def test_returns_none_when_kb_completely_empty():
    KnowledgeArticle.objects.all().delete()
    assert find_article_for_category("software") is None
