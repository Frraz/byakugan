"""Serializers de inventário: Asset e Service (RF007)."""

from __future__ import annotations

from rest_framework import serializers

from .models import Asset, Service, Technology


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


class AssetSerializer(serializers.ModelSerializer):
    """Ativo do inventário (visão de lista)."""

    class Meta:
        model = Asset
        fields = ("id", "ip", "hostname", "domain", "os", "status", "created_at")
        read_only_fields = fields


class AssetDetailSerializer(AssetSerializer):
    """Ativo com serviços e tecnologias aninhados (visão de detalhe)."""

    services = ServiceSerializer(many=True, read_only=True)
    technologies = TechnologySerializer(many=True, read_only=True)

    class Meta(AssetSerializer.Meta):
        fields = (*AssetSerializer.Meta.fields, "services", "technologies")
        read_only_fields = fields
