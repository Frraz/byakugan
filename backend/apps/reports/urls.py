"""Rotas do app reports (montadas sob /api/)."""

from rest_framework.routers import DefaultRouter

from .views import ReportViewSet

app_name = "reports"

router = DefaultRouter()
router.register("reports", ReportViewSet, basename="report")

urlpatterns = router.urls
