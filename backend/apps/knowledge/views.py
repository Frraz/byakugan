"""Views da Knowledge Base (RF014).

Views finas: a única regra de negócio (RN013) vive no serializer.
"""

from __future__ import annotations

from rest_framework import viewsets

from apps.core.audit import client_ip, record_audit
from apps.core.permissions import ReadOnlyOrAnalyst

from .models import KnowledgeArticle
from .serializers import KnowledgeArticleSerializer


class KnowledgeArticleViewSet(viewsets.ModelViewSet):
    """CRUD de artigos. Leitura: qualquer autenticado; escrita: analyst/admin;
    exclusão: admin (RN006). Diferente de Scan/Report/Finding, artigos **podem**
    ser atualizados — não são histórico imutável (RN003 não se aplica aqui).
    """

    queryset = KnowledgeArticle.objects.all()
    serializer_class = KnowledgeArticleSerializer
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["category"]
    search_fields = ["title", "summary", "category"]
    ordering_fields = ["created_at", "title", "category"]

    def perform_create(self, serializer: KnowledgeArticleSerializer) -> None:
        article = serializer.save()
        record_audit(
            "knowledge.create",
            user=self.request.user,
            severity="info",
            source=client_ip(self.request),
            article_id=str(article.id),
            slug=article.slug,
        )

    def perform_update(self, serializer: KnowledgeArticleSerializer) -> None:
        article = serializer.save()
        record_audit(
            "knowledge.update",
            user=self.request.user,
            severity="info",
            source=client_ip(self.request),
            article_id=str(article.id),
            slug=article.slug,
        )

    def perform_destroy(self, instance: KnowledgeArticle) -> None:
        record_audit(
            "knowledge.delete",
            user=self.request.user,
            severity="warning",
            source=client_ip(self.request),
            article_id=str(instance.id),
            slug=instance.slug,
        )
        super().perform_destroy(instance)
