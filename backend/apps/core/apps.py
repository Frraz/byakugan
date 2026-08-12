"""Configuração do app core."""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """App transversal: BaseModel, health check e logging."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core"
    verbose_name = "Core"
