"""Configuração do app scans."""

from django.apps import AppConfig


class ScansConfig(AppConfig):
    """App do motor de análise: scans, vulnerabilidades e findings."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.scans"
    verbose_name = "Scans"
