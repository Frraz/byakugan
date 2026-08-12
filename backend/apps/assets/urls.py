"""Rotas do app assets (montadas sob /api/)."""

from rest_framework.routers import DefaultRouter

from .views import AssetViewSet

app_name = "assets"

router = DefaultRouter()
router.register("assets", AssetViewSet, basename="asset")

urlpatterns = router.urls
