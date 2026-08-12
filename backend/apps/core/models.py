"""Modelos base compartilhados por todo o projeto."""

import uuid

from django.conf import settings
from django.db import models


class BaseModel(models.Model):
    """Modelo base com UUID como PK e timestamps de auditoria.

    Todos os modelos de domínio do Byakugan devem herdar desta classe.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ["-created_at"]


class AuditLog(models.Model):
    """Trilha de auditoria imutável de eventos sensíveis (RNF007, RN011).

    Registros são append-only: uma vez criados não podem ser alterados nem
    apagados pela aplicação (o método ``save`` bloqueia updates).
    """

    class Severity(models.TextChoices):
        INFO = "info", "Informativo"
        WARNING = "warning", "Atenção"
        CRITICAL = "critical", "Crítico"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=100, db_index=True)
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.INFO)
    source = models.CharField(max_length=64, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [models.Index(fields=["action", "timestamp"])]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.action} @ {self.timestamp:%Y-%m-%d %H:%M:%S}"

    def save(self, *args, **kwargs) -> None:
        """Impede atualização de registros já persistidos (imutabilidade)."""
        if self._state.adding is False:
            raise ValueError("AuditLog é imutável e não pode ser atualizado.")
        super().save(*args, **kwargs)
