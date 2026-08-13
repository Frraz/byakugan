"""Serializers de inventário: Asset e Service (RF007)."""

from __future__ import annotations

from rest_framework import serializers

from .models import Asset, DnsRecord, Service, Technology


class TechnologySerializer(serializers.ModelSerializer):
    """Tecnologia identificada num ativo (technology profile — Fase 2)."""

    class Meta:
        model = Technology
        fields = (
            "id",
            "asset",
            "category",
            "name",
            "version",
            "source",
            "evidence",
            "confidence",
            "created_at",
        )
        read_only_fields = fields


class ServiceSerializer(serializers.ModelSerializer):
    """Serviço exposto em um ativo."""

    class Meta:
        model = Service
        fields = (
            "id",
            "asset",
            "port",
            "protocol",
            "service_name",
            "product",
            "version",
            "created_at",
        )
        read_only_fields = fields


class DnsRecordSerializer(serializers.ModelSerializer):
    """Registro DNS não-A/AAAA descoberto de um domínio (Fase 3)."""

    class Meta:
        model = DnsRecord
        fields = ("id", "asset", "domain", "record_type", "value", "created_at")
        read_only_fields = fields


class AssetSerializer(serializers.ModelSerializer):
    """Ativo do inventário (visão de lista)."""

    findings_count = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = ("id", "ip", "hostname", "domain", "os", "status", "findings_count", "created_at")
        read_only_fields = fields

    def get_findings_count(self, obj: Asset) -> int:
        """Total de findings do ativo — annotation da view ou fallback com uma query."""
        annotated = getattr(obj, "findings_total", None)
        if annotated is not None:
            return annotated
        return obj.findings.count()


class AssetDetailSerializer(AssetSerializer):
    """Ativo com serviços, tecnologias e registros DNS aninhados (visão de detalhe)."""

    services = ServiceSerializer(many=True, read_only=True)
    technologies = TechnologySerializer(many=True, read_only=True)
    dns_records = DnsRecordSerializer(many=True, read_only=True)

    class Meta(AssetSerializer.Meta):
        fields = (*AssetSerializer.Meta.fields, "services", "technologies", "dns_records")
        read_only_fields = fields
