"""Serializers do motor de scans: Target, Scan e Finding."""

from __future__ import annotations

from typing import Any

from django.db.models import Count
from rest_framework import serializers

from .models import (
    Evidence,
    ExploitationPlaybook,
    Finding,
    FindingTriage,
    Scan,
    Severity,
    Target,
    Vulnerability,
)
from .validators import InvalidTarget, classify_target


class TargetSerializer(serializers.ModelSerializer):
    """Cadastro/consulta de alvos autorizados (RF004, RN001)."""

    kind = serializers.CharField(read_only=True)
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)
    scans_count = serializers.IntegerField(read_only=True, default=0)

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
            "scans_count",
            "created_by",
            "created_at",
        )
        read_only_fields = ("id", "kind", "scans_count", "created_by", "created_at")

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

    def update(self, instance: Target, validated_data: dict[str, Any]) -> Target:
        if "value" in validated_data:
            validated_data["kind"] = classify_target(validated_data["value"])
        return super().update(instance, validated_data)


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Catálogo de vulnerabilidades conhecidas (geralmente um CVE — RF008)."""

    class Meta:
        model = Vulnerability
        fields = (
            "id",
            "cve",
            "title",
            "severity",
            "cvss_score",
            "cvss_vector",
            "description",
            "references",
            "created_at",
        )
        read_only_fields = fields


class AssetSummarySerializer(serializers.Serializer):
    """Resumo de um ativo aninhado em um finding (evita request extra na UI)."""

    id = serializers.UUIDField(read_only=True)
    hostname = serializers.CharField(read_only=True)
    ip = serializers.IPAddressField(read_only=True, allow_null=True)
    domain = serializers.CharField(read_only=True)


class ScanSummarySerializer(serializers.Serializer):
    """Resumo de um scan aninhado em um finding."""

    id = serializers.UUIDField(read_only=True)
    target = serializers.CharField(read_only=True)
    scan_type = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)


class FindingSerializer(serializers.ModelSerializer):
    """Ocorrência de vulnerabilidade num ativo (RN008).

    ``scan``, ``asset`` e ``vulnerability`` são serializados aninhados
    (somente leitura) para que a UI exiba contexto sem requests extras.
    """

    scan = ScanSummarySerializer(read_only=True)
    asset = AssetSummarySerializer(read_only=True)
    vulnerability = VulnerabilitySerializer(read_only=True)
    triage_status = serializers.SerializerMethodField()

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
            "dedup_key",
            "playbook_key",
            "triage_status",
            "created_at",
        )
        read_only_fields = fields

    def get_triage_status(self, obj: Finding) -> str:
        """Status de triagem do achado lógico (por dedup_key) — annotation da view ou fallback."""
        annotated = getattr(obj, "triage_status", None)
        if annotated is not None:
            return annotated
        status = (
            FindingTriage.objects.filter(dedup_key=obj.dedup_key)
            .values_list("status", flat=True)
            .first()
        )
        return status or FindingTriage.Status.OPEN


class FindingTriageSerializer(serializers.ModelSerializer):
    """Estado de triagem de um achado lógico (Fase 5 — toda mudança é auditada, RN011)."""

    updated_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = FindingTriage
        fields = (
            "id",
            "dedup_key",
            "asset",
            "status",
            "note",
            "updated_by",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class FindingTriageInputSerializer(serializers.Serializer):
    """Entrada para triar um finding: ``POST /findings/{id}/triage/``."""

    status = serializers.ChoiceField(choices=FindingTriage.Status.choices)
    note = serializers.CharField(required=False, allow_blank=True, default="")


class ScanSerializer(serializers.ModelSerializer):
    """Representação de leitura de um scan, com contexto agregado para a UI."""

    target_name = serializers.SerializerMethodField()
    findings_count = serializers.SerializerMethodField()
    severity_counts = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = (
            "id",
            "created_by",
            "target_ref",
            "target",
            "target_name",
            "scan_type",
            "status",
            "authorized_by",
            "authorization_scope",
            "options",
            "progress",
            "phase",
            "started_at",
            "finished_at",
            "failure_reason",
            "findings_count",
            "severity_counts",
            "created_at",
        )
        read_only_fields = fields

    def get_target_name(self, obj: Scan) -> str | None:
        """Nome do target cadastrado, se o vínculo ainda existir."""
        return obj.target_ref.name if obj.target_ref_id and obj.target_ref else None

    def get_findings_count(self, obj: Scan) -> int:
        """Total de findings — annotation da view ou fallback com uma query."""
        annotated = getattr(obj, "findings_total", None)
        if annotated is not None:
            return annotated
        return obj.findings.count()

    def get_severity_counts(self, obj: Scan) -> dict[str, int]:
        """Contagem de findings por severidade (``{"critical": n, ...}``)."""
        if getattr(obj, f"sev_{Severity.CRITICAL}", None) is not None:
            return {sev: getattr(obj, f"sev_{sev}") for sev in Severity.values}
        counts = dict.fromkeys(Severity.values, 0)
        rows = obj.findings.values("severity").annotate(total=Count("id"))
        counts.update({row["severity"]: row["total"] for row in rows})
        return counts


class FindingRefSerializer(serializers.Serializer):
    """Resumo de finding aninhado numa evidência de exploração."""

    id = serializers.UUIDField(read_only=True)
    title = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True)
    category = serializers.CharField(read_only=True)
    playbook_key = serializers.CharField(read_only=True)


class EvidenceSerializer(serializers.ModelSerializer):
    """Resultado imutável de uma exploração automatizada (aba Evidências)."""

    finding = FindingRefSerializer(read_only=True)
    asset = AssetSummarySerializer(read_only=True)

    class Meta:
        model = Evidence
        fields = (
            "id",
            "finding",
            "scan",
            "asset",
            "playbook_key",
            "status",
            "impact_level",
            "proof",
            "steps_performed",
            "chain",
            "roe_profile",
            "created_at",
        )
        read_only_fields = fields


class ExploitationPlaybookSerializer(serializers.ModelSerializer):
    """Guia curado de exploração por classe de vulnerabilidade (aba Evidências)."""

    class Meta:
        model = ExploitationPlaybook
        fields = (
            "id",
            "key",
            "title",
            "category",
            "vuln_class",
            "summary",
            "prerequisites",
            "steps",
            "escalation_path",
            "max_impact",
            "tools",
            "references",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")


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
    options = serializers.JSONField(required=False, allow_null=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        if not attrs.get("target_ref") and not attrs.get("target"):
            raise serializers.ValidationError(
                "Informe um target_ref cadastrado ou os campos de alvo inline."
            )
        return attrs
