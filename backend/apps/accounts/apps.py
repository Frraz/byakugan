"""Configuração do app accounts."""

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    """App de identidade, autenticação e RBAC."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.accounts"
    verbose_name = "Accounts"
