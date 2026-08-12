"""Rotas do app knowledge (montadas sob /api/)."""

from rest_framework.routers import DefaultRouter

from .views import KnowledgeArticleViewSet

app_name = "knowledge"

router = DefaultRouter()
router.register("knowledge-base", KnowledgeArticleViewSet, basename="knowledge-article")

urlpatterns = router.urls
