"""Rotas do app scans (montadas sob /api/)."""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    EvidenceViewSet,
    ExploitationPlaybookViewSet,
    FindingViewSet,
    RiskOverviewView,
    ScanViewSet,
    TargetViewSet,
    VulnerabilityViewSet,
)

app_name = "scans"

router = DefaultRouter()
router.register("targets", TargetViewSet, basename="target")
router.register("scans", ScanViewSet, basename="scan")
router.register("vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
router.register("findings", FindingViewSet, basename="finding")
router.register("evidence", EvidenceViewSet, basename="evidence")
router.register("playbooks", ExploitationPlaybookViewSet, basename="playbook")

urlpatterns = [
    path("risk/overview/", RiskOverviewView.as_view(), name="risk-overview"),
    path("", include(router.urls)),
]
