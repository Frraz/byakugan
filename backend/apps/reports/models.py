"""Modelo de relatório: rastreável ao scan de origem (RN005), imutável (RN003)."""

from django.conf import settings
from django.db import models

from apps.core.models import BaseModel
from apps.scans.models import Scan


class Report(BaseModel):
    """Relatório gerado a partir de um scan (executivo ou técnico).

    Nunca é atualizado após a criação: uma nova versão é sempre um novo
    registro (RN003). O artefato (PDF/CSV/JSON) fica em disco sob
    ``MEDIA_ROOT``; ``file_path`` guarda o caminho relativo.
    """

    class ReportType(models.TextChoices):
        EXECUTIVE = "executive", "Executivo"
        TECHNICAL = "technical", "Técnico"

    class Format(models.TextChoices):
        PDF = "pdf", "PDF"
        CSV = "csv", "CSV"
        JSON = "json", "JSON"

    scan = models.ForeignKey(Scan, on_delete=models.PROTECT, related_name="reports")
    report_type = models.CharField(max_length=20, choices=ReportType.choices)
    format = models.CharField(max_length=10, choices=Format.choices)
    file_path = models.CharField(max_length=500)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="reports",
    )

    def __str__(self) -> str:
        return f"Report {self.report_type}/{self.format} — scan {self.scan_id}"
