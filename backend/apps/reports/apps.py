"""Configuração do app reports."""

from django.apps import AppConfig


class ReportsConfig(AppConfig):
    """App de geração e exportação de relatórios (Fase 5)."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.reports"
    verbose_name = "Reports"
