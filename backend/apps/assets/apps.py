"""Configuração do app assets."""

from django.apps import AppConfig


class AssetsConfig(AppConfig):
    """App de inventário de ativos e serviços."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.assets"
    verbose_name = "Assets"
