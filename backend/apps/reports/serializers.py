"""Serializers de relatórios: Report (RF009, RF010)."""

from __future__ import annotations

from rest_framework import serializers

from apps.scans.models import Scan

from .models import Report


class ReportSerializer(serializers.ModelSerializer):
    """Representação de leitura de um relatório, com contexto do scan de origem."""

    scan_target = serializers.CharField(source="scan.target", read_only=True)
    scan_type = serializers.CharField(source="scan.scan_type", read_only=True)
    scan_finished_at = serializers.DateTimeField(source="scan.finished_at", read_only=True)
    file_size = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = (
            "id",
            "scan",
            "scan_target",
            "scan_type",
            "scan_finished_at",
            "report_type",
            "format",
            "file_path",
            "file_size",
            "created_by",
            "created_at",
        )
        read_only_fields = fields

    def get_file_size(self, obj: Report) -> int | None:
        """Tamanho do artefato em bytes, ou ``None`` se o arquivo não existir."""
        from .services import report_file_path

        try:
            return report_file_path(obj).stat().st_size
        except OSError:
            return None


class ReportCreateSerializer(serializers.Serializer):
    """Entrada para geração de relatório.

    A regra de negócio (scan precisa estar `completed` — RN012) vive em
    ``services.generate_report``; este serializer apenas valida o shape.
    """

    scan = serializers.PrimaryKeyRelatedField(queryset=Scan.objects.all())
    report_type = serializers.ChoiceField(choices=Report.ReportType.choices)
    format = serializers.ChoiceField(choices=Report.Format.choices)
