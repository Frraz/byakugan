"""Roteamento raiz da API do Byakugan."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("apps.core.urls")),
    path("api/auth/", include("apps.accounts.urls")),
    path("api/", include("apps.assets.urls")),
    path("api/", include("apps.scans.urls")),
]
