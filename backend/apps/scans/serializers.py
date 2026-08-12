"""Serializers do motor de scans: Target, Scan e Finding."""

from __future__ import annotations

from typing import Any

from rest_framework import serializers

from .models import Finding, Scan, Target
from .validators import InvalidTarget, classify_target


class TargetSerializer(serializers.ModelSerializer):
    """Cadastro/consulta de alvos autorizados (RF004, RN001)."""

    kind = serializers.CharField(read_only=True)
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Target
        fields = (
            "id",
            "name",
            "value",
            "kind",
            "authorized_by",
            "authorization_scope",
            "authorization_expires_at",
            "is_active",
            "created_by",
            "created_at",
        )
        read_only_fields = ("id", "kind", "created_by", "created_at")

    def validate_value(self, value: str) -> str:
        try:
            classify_target(value)  # RN001
        except InvalidTarget as exc:
            raise serializers.ValidationError(str(exc)) from exc
        return value.strip()

    def create(self, validated_data: dict[str, Any]) -> Target:
        validated_data["kind"] = classify_target(validated_data["value"])
        validated_data["created_by"] = self.context["request"].user
        return super().create(validated_data)


class FindingSerializer(serializers.ModelSerializer):
    """Ocorrência de vulnerabilidade num ativo (RN008)."""

    class Meta:
        model = Finding
        fields = (
            "id",
            "scan",
            "asset",
            "vulnerability",
            "category",
            "title",
            "severity",
            "cvss",
            "description",
            "evidence",
            "recommendation",
            "created_at",
        )
        read_only_fields = fields


class ScanSerializer(serializers.ModelSerializer):
    """Representação de leitura de um scan."""

    class Meta:
        model = Scan
        fields = (
            "id",
            "created_by",
            "target_ref",
            "target",
            "scan_type",
            "status",
            "authorized_by",
            "authorization_scope",
            "started_at",
            "finished_at",
            "failure_reason",
            "created_at",
        )
        read_only_fields = fields


class ScanCreateSerializer(serializers.Serializer):
    """Entrada para criação de scan (via target cadastrado ou inline).

    A lógica de criação (validações RN001/RN002/RN007) vive em
    ``services.create_scan``; este serializer apenas valida o shape da entrada.
    """

    scan_type = serializers.ChoiceField(
        choices=Scan.ScanType.choices, default=Scan.ScanType.DISCOVERY
    )
    target_ref = serializers.PrimaryKeyRelatedField(
        queryset=Target.objects.filter(is_active=True), required=False, allow_null=True
    )
    target = serializers.CharField(required=False, allow_blank=True)
    authorized_by = serializers.CharField(required=False, allow_blank=True)
    authorization_scope = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if not attrs.get("target_ref") and not attrs.get("target"):
            raise serializers.ValidationError(
                "Informe um target_ref cadastrado ou os campos de alvo inline."
            )
        return attrs
