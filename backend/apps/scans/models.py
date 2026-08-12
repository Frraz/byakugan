"""Modelos do motor de análise: Scan, Vulnerability e Finding.

Ver docs/database.md e docs/scanning-engine.md. Resultados são imutáveis (RN003).
"""

from django.conf import settings
from django.db import models

from apps.assets.models import Asset
from apps.core.models import BaseModel


class Severity(models.TextChoices):
    """Severidade compartilhada por vulnerabilidades e findings."""

    CRITICAL = "critical", "Crítica"
    HIGH = "high", "Alta"
    MEDIUM = "medium", "Média"
    LOW = "low", "Baixa"
    INFO = "info", "Informativa"


class Target(BaseModel):
    """Alvo cadastrado com autorização reutilizável (RF004, RN007).

    Centraliza o registro de autorização para que vários scans referenciem o
    mesmo alvo. Ver docs/database.md e docs/scanning-engine.md.
    """

    class Kind(models.TextChoices):
        HOST = "host", "Host"
        DOMAIN = "domain", "Domínio"
        IP = "ip", "IP"
        CIDR = "cidr", "CIDR"

    name = models.CharField(max_length=255)
    value = models.CharField(max_length=255)
    kind = models.CharField(max_length=10, choices=Kind.choices)
    authorized_by = models.CharField(max_length=255)
    authorization_scope = models.TextField()
    authorization_expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="targets",
    )

    def __str__(self) -> str:
        return f"{self.name} ({self.value})"


class Scan(BaseModel):
    """Execução de análise autorizada sobre um alvo.

    A autorização (``authorized_by`` + ``authorization_scope``) é obrigatória
    antes da execução (RN007). Estados seguem a máquina definida em RN010.
    """

    class ScanType(models.TextChoices):
        DISCOVERY = "discovery", "Discovery"
        FINGERPRINT = "fingerprint", "Fingerprint"
        VULNERABILITY = "vulnerability", "Vulnerability"
        FULL = "full", "Full"

    class Status(models.TextChoices):
        PENDING = "pending", "Pendente"
        RUNNING = "running", "Executando"
        COMPLETED = "completed", "Concluído"
        FAILED = "failed", "Falhou"
        CANCELLED = "cancelled", "Cancelado"

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="scans",
    )
    target_ref = models.ForeignKey(
        Target,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans",
    )
    target = models.CharField(max_length=255)
    scan_type = models.CharField(
        max_length=20, choices=ScanType.choices, default=ScanType.DISCOVERY
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    authorized_by = models.CharField(max_length=255)
    authorization_scope = models.TextField()
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    failure_reason = models.TextField(blank=True, default="")

    def __str__(self) -> str:
        return f"Scan {self.target} [{self.scan_type}] - {self.status}"


class Vulnerability(BaseModel):
    """Entrada de catálogo de vulnerabilidade (geralmente um CVE)."""

    cve = models.CharField(max_length=30, null=True, blank=True, db_index=True)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    cvss_vector = models.CharField(max_length=100, null=True, blank=True)
    description = models.TextField()
    references = models.JSONField(default=list, blank=True)

    def __str__(self) -> str:
        return self.cve or self.title


class Finding(BaseModel):
    """Ocorrência concreta de uma vulnerabilidade num ativo (RN008).

    Nenhum finding pode ser salvo sem descrição, evidência e recomendação.
    """

    scan = models.ForeignKey(Scan, on_delete=models.PROTECT, related_name="findings")
    asset = models.ForeignKey(Asset, on_delete=models.PROTECT, related_name="findings")
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    category = models.CharField(max_length=50)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    cvss = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    description = models.TextField()
    evidence = models.TextField()
    recommendation = models.TextField()

    def __str__(self) -> str:
        return f"{self.title} ({self.severity})"
