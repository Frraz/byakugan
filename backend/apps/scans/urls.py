"""Rotas do app scans (montadas sob /api/)."""

from rest_framework.routers import DefaultRouter

from .views import ScanViewSet, TargetViewSet

app_name = "scans"

router = DefaultRouter()
router.register("targets", TargetViewSet, basename="target")
router.register("scans", ScanViewSet, basename="scan")

urlpatterns = router.urls
