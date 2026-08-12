"""Testes de integração da API da Knowledge Base (RF014, RN013)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.knowledge.models import KnowledgeArticle

pytestmark = pytest.mark.django_db


def _payload(**overrides):
    payload = {
        "slug": "test-article",
        "title": "Artigo de teste",
        "category": "software",
        "summary": "resumo",
        "impact": "impacto",
        "remediation_steps": ["passo 1"],
    }
    payload.update(overrides)
    return payload


def test_list_requires_auth(api_client):
    assert api_client.get(reverse("knowledge:knowledge-article-list")).status_code == 401


def test_viewer_can_list_seeded_articles(viewer_client):
    resp = viewer_client.get(reverse("knowledge:knowledge-article-list"))
    assert resp.status_code == 200
    assert resp.data["count"] >= 6  # artigos semeados pela migração de dados


def test_filter_by_category(viewer_client):
    resp = viewer_client.get(reverse("knowledge:knowledge-article-list"), {"category": "tls"})
    assert resp.status_code == 200
    assert resp.data["count"] >= 1
    assert all(a["category"] == "tls" for a in resp.data["results"])


def test_search_by_title(viewer_client):
    resp = viewer_client.get(reverse("knowledge:knowledge-article-list"), {"search": "TLS"})
    assert resp.status_code == 200
    assert resp.data["count"] >= 1


def test_viewer_cannot_create_article(viewer_client):
    resp = viewer_client.post(
        reverse("knowledge:knowledge-article-list"), _payload(), format="json"
    )
    assert resp.status_code == 403


def test_analyst_creates_article(analyst_client):
    resp = analyst_client.post(
        reverse("knowledge:knowledge-article-list"), _payload(), format="json"
    )
    assert resp.status_code == 201
    assert KnowledgeArticle.objects.filter(slug="test-article").exists()


def test_rn013_rejects_article_without_remediation_steps(analyst_client):
    resp = analyst_client.post(
        reverse("knowledge:knowledge-article-list"),
        _payload(remediation_steps=[]),
        format="json",
    )
    assert resp.status_code == 400
    assert "RN013" in str(resp.data)


def test_analyst_updates_article(analyst_client):
    article = KnowledgeArticle.objects.create(
        slug="update-me",
        title="Antigo",
        category="software",
        summary="s",
        impact="i",
        remediation_steps=["a"],
    )
    resp = analyst_client.patch(
        reverse("knowledge:knowledge-article-detail", args=[article.id]),
        {"title": "Novo título"},
        format="json",
    )
    assert resp.status_code == 200
    article.refresh_from_db()
    assert article.title == "Novo título"


def test_only_admin_can_delete_article(analyst_client, admin_client):
    article = KnowledgeArticle.objects.create(
        slug="delete-me",
        title="X",
        category="software",
        summary="s",
        impact="i",
        remediation_steps=["a"],
    )
    url = reverse("knowledge:knowledge-article-detail", args=[article.id])
    assert analyst_client.delete(url).status_code == 403
    assert admin_client.delete(url).status_code == 204
