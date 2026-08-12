"""Rotas do app core."""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import AuditLogViewSet, HealthView

app_name = "core"

router = DefaultRouter()
router.register("audit-logs", AuditLogViewSet, basename="audit-log")

urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("", include(router.urls)),
]
