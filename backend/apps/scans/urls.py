"""Rotas do app scans (montadas sob /api/)."""

from rest_framework.routers import DefaultRouter

from .views import FindingViewSet, ScanViewSet, TargetViewSet, VulnerabilityViewSet

app_name = "scans"

router = DefaultRouter()
router.register("targets", TargetViewSet, basename="target")
router.register("scans", ScanViewSet, basename="scan")
router.register("vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
router.register("findings", FindingViewSet, basename="finding")

urlpatterns = router.urls
