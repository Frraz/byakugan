"""Configuração do app knowledge."""

from django.apps import AppConfig


class KnowledgeConfig(AppConfig):
    """App de conteúdo explicativo e de remediação (Knowledge Base — Fase 6)."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.knowledge"
    verbose_name = "Knowledge Base"
