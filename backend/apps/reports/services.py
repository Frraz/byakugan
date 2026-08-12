"""Orquestração da geração de relatórios (Fase 5).

Regra de negócio: relatórios só podem ser gerados a partir de scans
concluídos (RN012) — evita relatórios com dados parciais/inconsistentes de
um scan ainda em execução ou que falhou.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from django.conf import settings

from apps.core.exceptions import Conflict
from apps.scans.models import Scan

from .models import Report
from .rendering import EXTENSION_BY_FORMAT, render_report

REPORTS_SUBDIR = "reports"


class ScanNotCompleted(Conflict):
    """Scan ainda não concluído — não há dados finais para gerar relatório (RN012).

    Já é um ``APIException`` (via ``Conflict``, 409), então propaga direto do
    service para a resposta HTTP sem precisar de tratamento na view — mesmo
    padrão de ``services.create_scan`` (RN002).
    """

    default_detail = "Relatórios só podem ser gerados a partir de scans concluídos (RN012)."


def generate_report(*, scan: Scan, report_type: str, format: str, created_by) -> Report:
    """Renderiza o artefato do relatório e persiste o registro (RN003/RN005).

    Raises:
        ScanNotCompleted: Se o scan ainda não estiver `completed` (RN012).
    """
    if scan.status != Scan.Status.COMPLETED:
        raise ScanNotCompleted()

    content = render_report(scan, report_type, format)

    extension = EXTENSION_BY_FORMAT[format]
    relative_path = f"{REPORTS_SUBDIR}/{uuid.uuid4()}.{extension}"
    absolute_path = Path(settings.MEDIA_ROOT) / relative_path
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    absolute_path.write_bytes(content)

    return Report.objects.create(
        scan=scan,
        report_type=report_type,
        format=format,
        file_path=relative_path,
        created_by=created_by,
    )


def report_file_path(report: Report) -> Path:
    """Caminho absoluto do artefato de um relatório já gerado."""
    return Path(settings.MEDIA_ROOT) / report.file_path
