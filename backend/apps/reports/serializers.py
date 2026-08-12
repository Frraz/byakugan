"""Serializers de relatórios: Report (RF009, RF010)."""

from __future__ import annotations

from rest_framework import serializers

from apps.scans.models import Scan

from .models import Report


class ReportSerializer(serializers.ModelSerializer):
    """Representação de leitura de um relatório."""

    class Meta:
        model = Report
        fields = (
            "id",
            "scan",
            "report_type",
            "format",
            "file_path",
            "created_by",
            "created_at",
        )
        read_only_fields = fields


class ReportCreateSerializer(serializers.Serializer):
    """Entrada para geração de relatório.

    A regra de negócio (scan precisa estar `completed` — RN012) vive em
    ``services.generate_report``; este serializer apenas valida o shape.
    """

    scan = serializers.PrimaryKeyRelatedField(queryset=Scan.objects.all())
    report_type = serializers.ChoiceField(choices=Report.ReportType.choices)
    format = serializers.ChoiceField(choices=Report.Format.choices)
